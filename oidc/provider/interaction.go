// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider

import (
	"net/http"
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
	// ACRValues are the requested acr_values, by preference: voluntary
	// (Core §3.1.2.1) — the provider enforces none of them.
	ACRValues []string
	// EssentialACR lists the acr values of an essential acr claim request
	// (Core §5.5.1.1): the authentication MUST satisfy one of them.
	EssentialACR []string
	// Subjects, when non-empty, lists the only end-users the request may be
	// answered for — the sub of a valid id_token_hint, the value(s) of a
	// requested sub claim (Core §3.1.2.2, §5.5.1).
	Subjects []string
	// Claims are the individually requested claims (claims parameter, Core
	// §5.5); release them through Decision.Claims.
	Claims ClaimsRequest
	// LoginHint, Display, UILocales and ClaimsLocales are passed through
	// (Core §3.1.2.1, §5.2, §15.1): use them or ignore them, they never
	// fail a request.
	LoginHint     string
	Display       string
	UILocales     []string
	ClaimsLocales []string
	// OfflineAccess reports a requested offline_access scope (Core §11).
	OfflineAccess bool
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
// §11, §17.4); its zero value refuses it.
type OfflineAccessConsent int

const (
	// NoOfflineAccess ignores the offline_access request: the scope is
	// dropped from the grant, and no refresh token enabling offline access
	// is issued.
	NoOfflineAccess OfflineAccessConsent = iota
	// OfflineAccessPrompted grants it after the end-user consented in the
	// consent dialog the request asked for: valid only when
	// Request.Prompt.Consent is set (Core §11 "MUST ensure that the prompt
	// parameter contains consent").
	OfflineAccessPrompted
	// OfflineAccessByPolicy grants it under "other conditions for
	// processing the request permitting offline access" (Core §11) — the
	// application's documented policy, e.g. an explicit consent to offline
	// access recorded earlier for this client.
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
	// error answers server_error.
	Refusal error
	// Scope is the granted scope; empty grants the requested one. It may
	// narrow the request, never broaden it, and keeps openid for an OpenID
	// request.
	Scope string
	// Claims lists the individually requested claims (Request.Claims) the
	// end-user agreed to release; nil releases none. A name releases the
	// requested claim of that name and its language-tagged variants
	// ("name" releases "name#fr"), a tagged name only itself.
	Claims []string
	// OfflineAccess grants a requested offline_access scope (see
	// OfflineAccessConsent).
	OfflineAccess OfflineAccessConsent
	// InteractionStartedAt is, when the login of this request spanned
	// several HTTP requests, when the application started it — taken from
	// server-side state bound to this authorization request (e.g. keyed by
	// client_id, state and nonce), never from the session or from request
	// parameters. It becomes the reference of the freshness checks instead
	// of Request.ReceivedAt (see Request.Check), within
	// [ReceivedAt − MaxInteractionDuration, ReceivedAt + 5s]. Zero when the
	// end-user authenticated during this HTTP request.
	InteractionStartedAt time.Time
}
