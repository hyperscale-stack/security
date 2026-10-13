// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider

import (
	"errors"
	"strings"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
)

// Bounds on the authentication event an application approves with.
const (
	maxACRLength = 255
	maxAMRValues = 10
	maxAMRLength = 32
)

// Why an approval is refused although no protocol rule failed: the
// application broke the Interaction contract. The ErrorHook gets them, the
// client a bare server_error, and nothing is issued.
var (
	errForeignConsent        = errors.New("oidcprovider: OpenID request approved without the provider's ConsentFunc")
	errEventSubject          = errors.New("oidcprovider: the authentication names another subject, or one that is not 1 to 255 printable ASCII characters")
	errEventTime             = errors.New("oidcprovider: the authentication has no time, one at or before the Unix epoch, or one in the future")
	errEventACR              = errors.New("oidcprovider: the acr is over 255 bytes or not visible ASCII")
	errEventAMR              = errors.New("oidcprovider: the amr has more than 10 values, or one that is not 1 to 32 visible ASCII characters")
	errScopeWithoutOpenID    = errors.New("oidcprovider: an OpenID approval granted a scope without openid")
	errOfflineWithoutConsent = errors.New("oidcprovider: OfflineAccessPrompted without prompt=consent")
)

// errOnlyOfflineAccess is the cause of the access_denied answering an
// approval that grants nothing once its offline_access is dropped.
var errOnlyOfflineAccess = errors.New("oidcprovider: offline_access, the only scope granted, was not granted")

// completeAuthorization verifies an approved decision against the request
// and returns what the grant records: the authentication event and the
// released claims as its context, and the granted scope without an
// offline_access the end-user did not consent to.
func (p *Provider) completeAuthorization(ar *oauth2.AuthorizeRequest, consent oauth2.Consent, now time.Time) (oauth2.ExtensionGrant, error) {
	view, ok := ar.ExtensionRequest.(*authRequest)
	if !ok || view == nil {
		return oauth2.ExtensionGrant{}, errNoRequestView
	}

	result, ok := consent.ExtensionResult.(*authResult)

	if !view.openID {
		// An OAuth 2.0 request: no context; the realm rule and the
		// offline_access rule only. Without the provider's result, another
		// ConsentFunc approved it — OAuth 2.0 semantics, unchanged.
		if !ok || result == nil {
			return oauth2.ExtensionGrant{}, nil
		}

		if err := view.public().Check(result.event, time.Time{}); err != nil {
			return oauth2.ExtensionGrant{}, err
		}

		scope, _, err := view.offlineScope(consent.Scope, result.offline)

		return oauth2.ExtensionGrant{Scope: scope}, err
	}

	if !ok || result == nil {
		return oauth2.ExtensionGrant{}, errForeignConsent
	}

	if err := checkEvent(result.event, consent.Subject, now); err != nil {
		return oauth2.ExtensionGrant{}, err
	}

	if !hasScope(consent.Scope, ScopeOpenID) {
		return oauth2.ExtensionGrant{}, errScopeWithoutOpenID
	}

	if err := view.public().Check(result.event, result.startedAt); err != nil {
		return oauth2.ExtensionGrant{}, err
	}

	scope, offline, err := view.offlineScope(consent.Scope, result.offline)
	if err != nil {
		return oauth2.ExtensionGrant{}, err
	}

	data, err := grantContext{
		AuthTime: result.event.AuthTime.Unix(),
		ACR:      result.event.ACR,
		AMR:      result.event.AMR,
		Offline:  offline,
		IDToken:  released(view.claims.IDToken, result.claims),
		UserInfo: released(view.claims.UserInfo, result.claims),
	}.encode()
	if err != nil {
		return oauth2.ExtensionGrant{}, err
	}

	return oauth2.ExtensionGrant{Scope: scope, Data: data}, nil
}

// checkEvent checks the authentication event an application approved
// with: the consent's subject, 1 to 255 printable ASCII characters (Core
// §2); a time after the Unix epoch — auth_time is a positive NumericDate —
// not in the future beyond the clock skew; a bounded acr and amr.
func checkEvent(ev AuthenticationEvent, subject string, now time.Time) error {
	switch {
	case ev.Subject != subject || ev.Subject == "" || len(ev.Subject) > maxSubjectLength || !printableASCII(ev.Subject):
		return errEventSubject
	case ev.AuthTime.Unix() <= 0 || ev.AuthTime.After(now.Add(authTimeSkew)):
		return errEventTime
	case len(ev.ACR) > maxACRLength || !visibleASCII(ev.ACR):
		return errEventACR
	case len(ev.AMR) > maxAMRValues:
		return errEventAMR
	}

	for _, amr := range ev.AMR {
		if amr == "" || len(amr) > maxAMRLength || !visibleASCII(amr) {
			return errEventAMR
		}
	}

	return nil
}

// printableASCII reports whether s holds printable ASCII (%x20-7E) only.
func printableASCII(s string) bool {
	for i := range len(s) {
		if s[i] < 0x20 || s[i] > 0x7E {
			return false
		}
	}

	return true
}

// offlineScope applies OpenID Connect Core §11 to a granted scope holding
// offline_access: kept, and recorded as consented, when the end-user
// consented through a consent dialog — the prompt=consent one for an
// OpenID request — or under the application's other conditions; dropped —
// "MUST ignore the offline_access request" — otherwise, and always outside
// the authorization code flow. The rule applies to plain OAuth 2.0
// requests too: the provider gives offline_access one meaning. It returns
// the narrowed scope, "" when nothing changes, or access_denied when
// nothing would be left: a blank scope keeps the granted one
// (oauth2.ExtensionGrant).
func (v *authRequest) offlineScope(granted string, consent OfflineAccessConsent) (string, bool, error) {
	if !hasScope(granted, ScopeOfflineAccess) {
		return "", false, nil
	}

	if !v.codeFlow {
		// Core §11: "MUST ignore the offline_access request unless the
		// Client is using a response_type value that would result in an
		// Authorization Code being returned" — whatever the decision.
		consent = NoOfflineAccess
	}

	switch consent {
	case OfflineAccessPrompted:
		// prompt is no OAuth 2.0 parameter: a plain request needs none.
		if v.openID && !v.prompt.Consent {
			return "", false, errOfflineWithoutConsent
		}

		return "", true, nil
	case OfflineAccessByPolicy:
		return "", true, nil
	case NoOfflineAccess:
	}

	kept := make([]string, 0, len(v.scopes))

	for _, s := range strings.Fields(granted) {
		if s != ScopeOfflineAccess {
			kept = append(kept, s)
		}
	}

	if len(kept) == 0 {
		return "", false, oauth2.ErrAccessDenied.WithCause(errOnlyOfflineAccess)
	}

	return strings.Join(kept, " "), false, nil
}

// released returns the stored form of the requested claims the decision
// releases.
func released(requested []ClaimRequest, decision []string) []storedClaim {
	var out []ClaimRequest

	for _, c := range requested {
		if releases(decision, c.Name) {
			out = append(out, c)
		}
	}

	return storedClaims(out)
}
