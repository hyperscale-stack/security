// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider

import (
	"context"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
)

// Scope values (OpenID Connect Core §3.1.2.1, §5.4, §11).
const (
	// ScopeOpenID makes an authorization request an OpenID Connect
	// authentication request (Core §3.1.2.1).
	ScopeOpenID = "openid"
	// ScopeProfile requests the default profile claims at UserInfo.
	ScopeProfile = "profile"
	// ScopeEmail requests email and email_verified at UserInfo.
	ScopeEmail = "email"
	// ScopeAddress requests address at UserInfo.
	ScopeAddress = "address"
	// ScopePhone requests phone_number and phone_number_verified at UserInfo.
	ScopePhone = "phone"
	// ScopeOfflineAccess requests a refresh token enabling access while the
	// end-user is absent (Core §11): wire grant.Config.RefreshTokenScope to
	// it, and grant it only with the end-user's consent
	// ([Decision].OfflineAccess). The provider's §11 rules apply to OpenID
	// requests only: a plain OAuth 2.0 request keeps OAuth 2.0 semantics —
	// narrow its scope through Decision.Scope when it must not get one.
	ScopeOfflineAccess = "offline_access"
)

// ClaimsSource supplies end-user claims. The provider asks it for the
// claims of an ID Token — at the code exchange and at every refresh — and
// of a UserInfo response, naming in [ClaimsQuery].Names the only claims it
// may release; whatever else the source returns is dropped, and so are
// null and empty-string values (Core §5.3.2) and the protocol claims the
// provider sets itself (sub, iss, aud, exp, iat, auth_time, nonce, acr,
// amr, at_hash, …) — a source cannot override them.
//
// The provider queries it on every token exchange of an OpenID grant, an
// ID Token being issued or not: returning [ErrUnknownSubject] for an
// end-user that no longer exists or may no longer sign in stops the grant
// (invalid_grant, invalid_token at UserInfo). Any other error answers
// server_error. Implementations MUST be safe for concurrent use.
type ClaimsSource interface {
	Claims(ctx context.Context, q ClaimsQuery) (map[string]any, error)
}

// ClaimsTarget tells where the claims of a [ClaimsQuery] go.
type ClaimsTarget string

const (
	// ClaimsForIDToken targets an ID Token — or, with no Names, only checks
	// that the end-user is still valid (a refresh issuing no ID Token).
	ClaimsForIDToken ClaimsTarget = "id_token"
	// ClaimsForUserInfo targets a UserInfo response.
	ClaimsForUserInfo ClaimsTarget = "userinfo"
)

// ClaimsQuery asks a [ClaimsSource] for the claims of one end-user.
type ClaimsQuery struct {
	// Issuer is the realm the end-user belongs to.
	Issuer string
	// Subject is the end-user's sub within Issuer.
	Subject string
	// ClientID is the client the claims are released to.
	ClientID string
	// Target is where the claims go.
	Target ClaimsTarget
	// Names lists the claims the provider may release: those of the granted
	// scopes (UserInfo) and those the end-user agreed to release through the
	// claims parameter. A language-tagged variant of a listed name
	// ("name#fr", Core §5.2) is released with it. Empty: release nothing.
	Names []string
}

// Claim names the provider handles itself (OpenID Connect Core §2, §3.1.3.6).
const (
	claimIss      = "iss"
	claimSub      = "sub"
	claimAud      = "aud"
	claimExp      = "exp"
	claimIat      = "iat"
	claimAuthTime = "auth_time"
	claimNonce    = "nonce"
	claimACR      = "acr"
	claimAMR      = "amr"
	claimAtHash   = "at_hash"
	claimScope    = "scope"
)

// reservedClaims are the claims the provider sets itself, or that belong to
// another protocol: a ClaimsSource never supplies them, whatever it
// returns, and the provider never asks for them.
var reservedClaims = []string{
	claimIss, claimSub, claimAud, claimExp, claimIat, "nbf", "jti", claimAuthTime, claimNonce, claimACR, claimAMR, "azp",
	claimAtHash, "c_hash", "s_hash", "sid", "cnf", claimScope, "client_id", "typ", "_claim_names", "_claim_sources",
}

// scopeClaims are the claims each scope value requests from UserInfo (Core
// §5.4).
var scopeClaims = map[string][]string{
	ScopeProfile: {
		"name", "family_name", "given_name", "middle_name", "nickname", "preferred_username", "profile",
		"picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at",
	},
	ScopeEmail:   {"email", "email_verified"},
	ScopeAddress: {"address"},
	ScopePhone:   {"phone_number", "phone_number_verified"},
}

// reserved reports whether name — or its untagged name — is reserved.
func reserved(name string) bool {
	base, _, _ := strings.Cut(name, "#")

	return slices.Contains(reservedClaims, base)
}

// releasable maps the names a response may release to their acceptable
// values (none: any value): the claims of scopes, then the released claim
// requests, whose value constraints apply.
func releasable(requested []storedClaim, scopes []string) map[string][]json.RawMessage {
	out := map[string][]json.RawMessage{}

	for _, scope := range scopes {
		for _, name := range scopeClaims[scope] {
			out[name] = nil
		}
	}

	for _, c := range requested {
		if !reserved(c.Name) {
			out[c.Name] = c.Values
		}
	}

	return out
}

// queryNames lists the names of a release set, sorted.
func queryNames(allowed map[string][]json.RawMessage) []string {
	names := make([]string, 0, len(allowed))
	for name := range allowed {
		names = append(names, name)
	}

	slices.Sort(names)

	return names
}

// releaseClaims keeps, of what a ClaimsSource returned, the claims allowed
// lists — a language-tagged variant ("name#fr") with its untagged name —
// whose value is neither null nor an empty string (Core §5.3.2) and matches
// the request's value constraint, if any (Core §5.5.1). allowed never holds
// a reserved claim (see releasable), so none is ever kept.
func releaseClaims(src map[string]any, allowed map[string][]json.RawMessage) map[string]any {
	out := make(map[string]any, len(src))

	for name, v := range src {
		if v == nil {
			continue
		}

		if s, ok := v.(string); ok && s == "" {
			continue
		}

		values, ok := allowed[name]
		if !ok {
			base, _, _ := strings.Cut(name, "#")
			if values, ok = allowed[base]; !ok {
				continue
			}
		}

		if len(values) > 0 && !matchesAny(v, values) {
			continue
		}

		out[name] = v
	}

	return out
}

// matchesAny reports whether the claim value v equals one of values — an
// equality of JSON scalars (Core §5.5.1, §14): strings code point by code
// point, booleans, numbers numerically. An object or array matches nothing.
func matchesAny(v any, values []json.RawMessage) bool {
	encoded, err := json.Marshal(v)
	if err != nil {
		return false
	}

	got, ok := scalarOf(encoded)
	if !ok {
		return false
	}

	for _, raw := range values {
		if want, ok := scalarOf(raw); ok && want == got {
			return true
		}
	}

	return false
}

// scalarOf decodes a JSON scalar to a comparable value — a string, a bool
// or a finite float64 — or reports false: a number beyond float64 is no
// value (strconv.ParseFloat answers ±Inf with ErrRange, and JSON has no
// other infinite literal).
func scalarOf(raw []byte) (any, bool) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()

	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}

	switch x := v.(type) {
	case string, bool:
		return x, true
	case json.Number:
		f, err := strconv.ParseFloat(x.String(), 64)
		if err != nil {
			return nil, false
		}

		return f, true
	default:
		return nil, false
	}
}
