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
func (p *Provider) AuthorizeHandler(cfg oauth2.AuthorizeConfig) http.Handler {
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
//   - EssentialACR set and ev.ACR not among them: oauth2.ErrAccessDenied, a
//     failed authentication — oauth2.ErrLoginRequired under prompt=none,
//     where a step-up needs an interaction.
//
// The reference time is ReceivedAt, or interactionStartedAt when the login
// spanned several HTTP requests (see Decision.InteractionStartedAt); outside
// [ReceivedAt − MaxInteractionDuration, ReceivedAt + 5s] it answers
// oauth2.ErrServerError. Use it to decide whether a session can be reused
// or the end-user must log in.
func (r *Request) Check(ev AuthenticationEvent, interactionStartedAt time.Time) error {
	if ev.Issuer != r.Issuer {
		if r.OpenID {
			return oauth2.ErrLoginRequired.WithDescription("the end-user is not authenticated in this realm")
		}

		return oauth2.ErrAccessDenied.WithDescription("the end-user is not authenticated in this realm")
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
		return oauth2.ErrLoginRequired.WithDescription("the request designates another end-user")
	}

	if len(r.EssentialACR) > 0 && !slices.Contains(r.EssentialACR, ev.ACR) {
		if r.Prompt.None {
			return oauth2.ErrLoginRequired.WithDescription("the requested authentication context needs an interaction")
		}

		return oauth2.ErrAccessDenied.WithDescription("the authentication does not satisfy the requested context")
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
			return oauth2.ErrLoginRequired.WithDescription("the end-user must authenticate again")
		}
	case r.MaxAge != nil:
		if ref-authTime > int64(*r.MaxAge/time.Second) {
			return oauth2.ErrLoginRequired.WithDescription("the end-user authentication is too old")
		}
	}

	return nil
}
