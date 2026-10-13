// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
)

// MaxInteractionDuration bounds [Decision].InteractionStartedAt: a login
// interaction spanning several HTTP requests completes within it.
const MaxInteractionDuration = 15 * time.Minute

// Interaction is the application side of an authorization: end-user
// sessions within the request's issuer (realm), the login, account
// selection and consent user interface, consent records. The provider owns
// the protocol: it validates the request first, tells the Interaction what
// the request requires ([Request]), and verifies the [Decision] against it
// before anything is issued — a decision violating the request is refused,
// never silently honored.
//
// Implementations MUST be safe for concurrent use. They authenticate the
// end-user within [Request].Issuer only — a session of another realm is no
// authentication — and, when tenancy is finer than the issuer, also check
// the session's tenant against [Request].Client. When interacting, they
// MUST protect their pages against CSRF and clickjacking (OpenID Connect
// Core §3.1.2.3, RFC 6749 §10.12–§10.13), and never redirect with 307
// (Core §16.22).
type Interaction interface {
	// Authorize handles an interactive request — every OAuth 2.0 request
	// (Request.OpenID false) and every OpenID request without prompt=none.
	// It authenticates the end-user (reusing a session that satisfies
	// Request.Check, or rendering a login page), obtains consent, and
	// returns the decision — or (nil, nil) once it has written its own
	// response to w. An error answers server_error, its cause reaching the
	// server's ErrorHook only.
	Authorize(w http.ResponseWriter, r *http.Request, req *Request) (*Decision, error)

	// AuthorizeSilently handles an OpenID request with prompt=none (Core
	// §3.1.2.1, §3.1.2.3): it has no ResponseWriter, so it cannot display
	// anything. It decides from the existing session and consent records,
	// or refuses with oauth2.ErrLoginRequired, ErrConsentRequired,
	// ErrInteractionRequired or ErrAccountSelectionRequired (Core
	// §3.1.2.6). It MUST return a decision: (nil, nil) answers server_error.
	// Decision.InteractionStartedAt is ignored — there is no interaction.
	AuthorizeSilently(r *http.Request, req *Request) (*Decision, error)
}

// Prompt is the parsed prompt parameter (Core §3.1.2.1). Unknown values are
// ignored; none never comes with another value.
type Prompt struct {
	// None: the provider calls Interaction.AuthorizeSilently.
	None bool
	// Login: the end-user MUST authenticate again, within this
	// authorization (see Request.Check).
	Login bool
	// Consent: the end-user MUST be asked for consent; it is also the
	// condition of OfflineAccessPrompted.
	Consent bool
	// SelectAccount: the end-user SHOULD be asked to select an account.
	SelectAccount bool
}

// Request is the validated authorization request as the application sees
// it — a fresh copy for every call: changing it changes nothing the
// provider verifies.
type Request struct {
	// Issuer is the realm of the request: authenticate the end-user within
	// it only.
	Issuer string
	// Client is the registered client. Shared with the server: never
	// mutate it.
	Client oauth2.Client
	// RedirectURI is the validated redirection URI.
	RedirectURI string
	// Scopes are the requested scope values.
	Scopes []string
	// OfflineAccess reports a requested offline_access scope (Core §11) —
	// for every request, OpenID or plain OAuth 2.0: the provider keeps it
	// only when Decision.OfflineAccess grants it.
	OfflineAccess bool
	// OpenID reports an OpenID Connect authentication request (scope
	// openid). The fields below are only set for one.
	OpenID bool
	// ReceivedAt is when the provider received this HTTP request (server
	// clock): the reference of the freshness checks (see Check).
	ReceivedAt time.Time
	// Prompt is the parsed prompt parameter.
	Prompt Prompt
	// MaxAge is max_age (Core §3.1.2.1), nil when absent: the end-user MUST
	// have authenticated at most that long before the request.
	MaxAge *time.Duration
	// ACRValues are the acr values the request prefers, in order: those of
	// acr_values (Core §3.1.2.1), then those of a voluntary acr claim
	// request for the ID Token (§5.5.1.1) — once each, at most 32; an
	// acr_values over 2048 bytes is ignored. Voluntary: the provider
	// enforces none of them.
	ACRValues []string
	// EssentialACR lists the acr values of an essential acr claim request
	// (Core §5.5.1.1): the authentication MUST satisfy one of them.
	EssentialACR []string
	// Subjects, when non-empty, lists the only end-users the request may be
	// answered for — the sub of a valid id_token_hint, the value(s) of a
	// requested sub claim (Core §3.1.2.2, §5.5.1).
	Subjects []string
	// Claims are the individually requested claims (claims parameter, Core
	// §5.5) the provider may release — protocol claims, their case variants
	// and other spellings of the claims it knows are left out (see
	// [ClaimsSource]); release them through Decision.Claims. Subjects and
	// EssentialACR hold what the sub and acr requests require.
	Claims ClaimsRequest
	// LoginHint, Display, UILocales and ClaimsLocales are passed through
	// (Core §3.1.2.1, §5.2, §15.1): use them or ignore them, they never
	// fail a request. ClaimsLocales reaches the Interaction only — the
	// ClaimsSource is not told: it returns the language-tagged claims
	// (Core §5.2) it has, and the provider releases those requested. Oversized or invalid UTF-8 values are ignored: a
	// login_hint over 1024 bytes, a display over 255 bytes, ui_locales or
	// claims_locales over 2048 bytes — of which the first 32 values are
	// kept.
	LoginHint     string
	Display       string
	UILocales     []string
	ClaimsLocales []string
}

// AuthenticationEvent is the end-user authentication a grant rests on: it
// is recorded with the grant and carried unchanged by every token derived
// from it — ID Tokens issued at a refresh keep its auth_time, acr and amr
// (Core §12.2).
type AuthenticationEvent struct {
	// Issuer is the realm the end-user authenticated in (from the session);
	// it MUST equal Request.Issuer.
	Issuer string
	// Subject is the end-user's sub: locally unique, never reassigned, the
	// same for every client (public subject type, Core §8), at most 255
	// printable ASCII characters (Core §2).
	Subject string
	// AuthTime is when the end-user actively authenticated — not when the
	// session was last used. Required for OpenID requests.
	AuthTime time.Time
	// ACR is the authentication context class reference the authentication
	// satisfied (Core §2), at most 255 printable ASCII characters; empty for
	// none.
	ACR string
	// AMR are the authentication method references (RFC 8176), at most 10
	// values of at most 32 visible ASCII characters.
	AMR []string
}

// OfflineAccessConsent says why a requested offline_access is granted (Core
// §11, §17.4); its zero value refuses it. It applies to every request the
// provider serves — offline_access has one meaning at its server. A request
// returning no authorization code would always have its offline_access
// ignored (§11); [Provider.AuthorizeHandler] serves none.
type OfflineAccessConsent int

const (
	// NoOfflineAccess ignores the offline_access request: the scope is
	// dropped from the grant, and no refresh token enabling offline access
	// is issued — an approval granting nothing else answers access_denied.
	NoOfflineAccess OfflineAccessConsent = iota
	// OfflineAccessPrompted grants it after the end-user consented in the
	// consent dialog — for an OpenID request, the one it asked for: valid
	// only when Request.Prompt.Consent is set (Core §11 "MUST ensure that
	// the prompt parameter contains consent"); prompt being no OAuth 2.0
	// parameter, a plain OAuth 2.0 request needs none.
	OfflineAccessPrompted
	// OfflineAccessByPolicy grants it under "other conditions for
	// processing the request permitting offline access" (Core §11) — the
	// application's documented policy, e.g. an explicit consent to offline
	// access recorded earlier for this client, or plain OAuth 2.0 clients
	// for which offline_access needs no end-user choice.
	OfflineAccessByPolicy
)

// Decision is the application's answer to an authorization request.
// Exactly one of Authentication (approval) and Refusal is set; neither
// means the end-user denied the request (access_denied).
type Decision struct {
	// Authentication approves the request for this authentication event.
	Authentication *AuthenticationEvent
	// Refusal refuses the request with this protocol error — an
	// authorization-endpoint code (RFC 6749 §4.1.2.1, Core §3.1.2.6), e.g.
	// oauth2.ErrLoginRequired, or what Request.Check returned. Any other
	// error answers server_error. Its description travels to the client:
	// it must not describe the browser's sessions (keep the sentinels'
	// own).
	Refusal error
	// Scope is the granted scope; empty grants the requested one. It may
	// narrow the request, never broaden it, and keeps openid for an OpenID
	// request.
	Scope string
	// Claims lists the individually requested claims (Request.Claims) the
	// end-user agreed to release; nil releases none. A name releases the
	// requested claim of that name and its language-tagged variants
	// ("name" releases "name#fr"), a tagged name only itself. One list
	// serves both targets: a name releases its ID Token and its UserInfo
	// requests alike. A name Request.Claims does not hold releases nothing.
	Claims []string
	// OfflineAccess grants a requested offline_access scope, for an OpenID
	// or a plain OAuth 2.0 request alike (see OfflineAccessConsent):
	// without it, offline_access is dropped from the grant.
	OfflineAccess OfflineAccessConsent
	// InteractionStartedAt is, when the login of this request spanned
	// several HTTP requests, when the application started it — taken from
	// server-side state bound to this browser and this authorization
	// request (e.g. keyed by the browser's session and by client_id,
	// state, nonce and code_challenge), never from the session's own
	// values or from request parameters: whoever knows a request's
	// parameters must not be able to backdate its start for another
	// browser. It becomes the reference of the freshness checks instead
	// of Request.ReceivedAt (see Request.Check), within
	// [ReceivedAt − MaxInteractionDuration, ReceivedAt + 5s]. Zero when the
	// end-user authenticated during this HTTP request.
	InteractionStartedAt time.Time
}

// authTimeSkew tolerates clock skew between the instances that record an
// authentication and the one that checks it.
const authTimeSkew = 5 * time.Second

// Why an interaction's answer is refused although no protocol rule failed:
// the causes the ErrorHook gets, the client gets a bare server_error.
var (
	errNoRequestView         = errors.New("oidcprovider: no validated request view")
	errSilentWithoutDecision = errors.New("oidcprovider: AuthorizeSilently returned no decision")
	errContradictoryDecision = errors.New("oidcprovider: a decision both approves and refuses")
	errRefusalNotProtocol    = errors.New("oidcprovider: a refusal is not an OAuth 2.0 protocol error")
	errInteractionStart      = errors.New("oidcprovider: InteractionStartedAt outside its window")
)

// Why Request.Check refuses an authentication: causes for the ErrorHook.
// The client only ever gets the sentinel's fixed description — under
// prompt=none, a reason would tell a client what sessions the browser
// holds (another realm, another end-user, a stale one).
var (
	errOtherRealm      = errors.New("oidcprovider: the authentication belongs to another realm")
	errReauthenticate  = errors.New("oidcprovider: the end-user must authenticate again (prompt=login, max_age=0)")
	errAuthTooOld      = errors.New("oidcprovider: the authentication is older than max_age")
	errOtherEndUser    = errors.New("oidcprovider: the request designates another end-user")
	errACRNotSatisfied = errors.New("oidcprovider: the authentication does not satisfy the essential acr")
)

// authResult is the trusted outcome of an approval, carried from the
// provider's ConsentFunc to CompleteAuthorization as
// Consent.ExtensionResult — a type only the provider builds.
type authResult struct {
	event     AuthenticationEvent
	claims    []string
	offline   OfflineAccessConsent
	startedAt time.Time
}

// AuthorizeHandler returns the authorization endpoint ([Paths].Authorize,
// GET and POST, OpenID Connect Core §3.1.2.1): the server's, with the
// provider as its ConsentFunc. Every OpenID request must come through it:
// one served by Server().AuthorizeHandler with another ConsentFunc is
// refused (server_error) before that ConsentFunc runs. cfg configures the
// endpoint as for oauth2.Server.AuthorizeHandler.
//
// The provider serves the authorization code flow only — RFC 9700 §2.1.2
// deprecates the implicit grant, and the discovery document advertises
// response_type code alone: AuthorizeHandler panics when cfg enables the
// implicit flow (AllowImplicit), before the server records it, as the
// server panics on its own misconfigurations. A handler built from
// Server().AuthorizeHandler is not checked: never enable the implicit flow
// there either (see [Provider.Server]).
func (p *Provider) AuthorizeHandler(cfg oauth2.AuthorizeConfig) http.Handler {
	if cfg.AllowImplicit {
		panic("oidcprovider: AuthorizeHandler: the provider serves no implicit flow (AllowImplicit)")
	}

	h := p.server.AuthorizeHandler(cfg, p.consent)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), markerKey{}, p)))
	})
}

// consent is the server's ConsentFunc: it hands the application a copy of
// the validated request — without ResponseWriter for prompt=none — and
// turns its Decision into the server's Consent.
func (p *Provider) consent(w http.ResponseWriter, r *http.Request, ar *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
	view, ok := ar.ExtensionRequest.(*authRequest)
	if !ok || view == nil {
		return nil, errNoRequestView
	}

	req := view.public()
	silent := view.openID && view.prompt.None

	var (
		decision *Decision
		err      error
	)

	if silent {
		decision, err = p.cfg.Interaction.AuthorizeSilently(r, req)
		if err == nil && decision == nil {
			err = errSilentWithoutDecision
		}
	} else {
		decision, err = p.cfg.Interaction.Authorize(w, r, req)
		if err == nil && decision == nil {
			return nil, nil // the application answered: its login page
		}
	}

	if err != nil {
		return nil, fmt.Errorf("oidcprovider: interaction: %w", err)
	}

	return consentOf(decision, silent)
}

// consentOf turns a Decision into the server's Consent. The approval's
// result is a copy: the application keeps no handle on what is verified.
func consentOf(d *Decision, silent bool) (*oauth2.Consent, error) {
	switch {
	case d.Refusal != nil && d.Authentication != nil:
		return nil, errContradictoryDecision
	case d.Refusal != nil:
		var oe *oauth2.Error
		if !errors.As(d.Refusal, &oe) || oe == nil {
			return nil, fmt.Errorf("%w: %w", errRefusalNotProtocol, d.Refusal)
		}

		return &oauth2.Consent{Refusal: oe}, nil
	case d.Authentication == nil:
		return &oauth2.Consent{}, nil // the end-user denied: access_denied
	}

	result := &authResult{
		event: *d.Authentication, claims: slices.Clone(d.Claims), offline: d.OfflineAccess,
		startedAt: d.InteractionStartedAt,
	}
	result.event.AMR = slices.Clone(d.Authentication.AMR)

	// There is no interaction under prompt=none: InteractionStartedAt could
	// only stretch max_age.
	if silent {
		result.startedAt = time.Time{}
	}

	return &oauth2.Consent{Approved: true, Subject: result.event.Subject, Scope: d.Scope, ExtensionResult: result}, nil
}

// Check returns nil when ev satisfies the request, or the refusal the
// provider answers if ev is approved as is — the rules of OpenID Connect
// Core §3.1.2.1–§3.1.2.3, §5.5.1 and §5.5.1.1 the provider applies to every
// approval:
//   - ev.Issuer differs from Issuer (a session of another realm):
//     oauth2.ErrLoginRequired — oauth2.ErrAccessDenied for an OAuth 2.0
//     request, which no other rule concerns;
//   - prompt=login or max_age=0: ev.AuthTime before the reference time;
//     max_age=N: ev.AuthTime more than N seconds before it — both
//     oauth2.ErrLoginRequired, in whole seconds (auth_time is a NumericDate);
//   - Subjects set and ev.Subject not among them: oauth2.ErrLoginRequired;
//   - EssentialACR set and ev.ACR not among them — an empty ev.ACR never
//     satisfies it: oauth2.ErrAccessDenied, a failed authentication —
//     oauth2.ErrLoginRequired under prompt=none, where a step-up needs an
//     interaction.
//
// Each refusal carries the sentinel's own description — the reason is its
// cause, for the ErrorHook only: on the wire, a session of another realm,
// of another end-user or a stale one reads as no session at all. An
// Interaction refusing with what Check returns, or with the sentinels,
// keeps that property; its own descriptions must not describe the
// session either.
//
// The reference time is ReceivedAt, or interactionStartedAt when the login
// spanned several HTTP requests (see Decision.InteractionStartedAt); outside
// [ReceivedAt − MaxInteractionDuration, ReceivedAt + 5s] it answers
// oauth2.ErrServerError. Use it to decide whether a session can be reused
// or the end-user must log in.
func (r *Request) Check(ev AuthenticationEvent, interactionStartedAt time.Time) error {
	if ev.Issuer != r.Issuer {
		if r.OpenID {
			return oauth2.ErrLoginRequired.WithCause(errOtherRealm)
		}

		return oauth2.ErrAccessDenied.WithCause(errOtherRealm)
	}

	if !r.OpenID {
		return nil
	}

	reference := r.ReceivedAt

	if !interactionStartedAt.IsZero() {
		if interactionStartedAt.Before(r.ReceivedAt.Add(-MaxInteractionDuration)) ||
			interactionStartedAt.After(r.ReceivedAt.Add(authTimeSkew)) {
			return oauth2.ErrServerError.WithCause(errInteractionStart)
		}

		reference = interactionStartedAt
	}

	if err := r.checkFreshness(ev, reference); err != nil {
		return err
	}

	if len(r.Subjects) > 0 && !slices.Contains(r.Subjects, ev.Subject) {
		return oauth2.ErrLoginRequired.WithCause(errOtherEndUser)
	}

	if len(r.EssentialACR) > 0 && (ev.ACR == "" || !slices.Contains(r.EssentialACR, ev.ACR)) {
		if r.Prompt.None {
			return oauth2.ErrLoginRequired.WithCause(errACRNotSatisfied)
		}

		return oauth2.ErrAccessDenied.WithCause(errACRNotSatisfied)
	}

	return nil
}

// checkFreshness applies prompt=login and max_age against reference.
// max_age=0 needs no case of its own: "elapsed time greater than 0" is
// exactly prompt=login's rule, as Core §3.1.2.1 notes.
func (r *Request) checkFreshness(ev AuthenticationEvent, reference time.Time) error {
	authTime, ref := ev.AuthTime.Unix(), reference.Unix()

	switch {
	case r.Prompt.Login:
		if authTime < ref {
			return oauth2.ErrLoginRequired.WithCause(errReauthenticate)
		}
	case r.MaxAge != nil:
		if ref-authTime > int64(*r.MaxAge/time.Second) {
			return oauth2.ErrLoginRequired.WithCause(errAuthTooOld)
		}
	}

	return nil
}
