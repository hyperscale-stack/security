// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/hyperscale-stack/security/oauth2/internal/param"
)

// TokenHandler returns the http.Handler for the RFC 6749 §3.2 /token
// endpoint. The handler:
//
//  1. Requires POST, and reads the parameters from the
//     application/x-www-form-urlencoded body (RFC 6749 §3.2): a body of
//     another type is not parsed, so the request carries no parameter and
//     fails as such (invalid_client or invalid_request).
//  2. Resolves the issuer and authenticates the client at it via the
//     configured ClientAuthenticators (a client bound to other issuers is
//     unknown, see [IssuerBoundClient]).
//  3. Looks up the grant_type, checks that the client declares it
//     ([ClientAllowsGrantType]; unauthorized_client otherwise, before the
//     grant runs, custom grants included) and dispatches to the matching
//     Grant.
//  4. Serializes the response per RFC 6749 §5.1 (success) — plus the
//     id_token an [Extension] adds (OpenID Connect Core §3.1.3.3) — or §5.2
//     (error).
//
// Its query and body are bounded by [ServerConfig.MaxRequestBytes]
// (invalid_request beyond), like those of /revoke and /introspect.
//
// The parameters of RFC 6749 and RFC 7636 the endpoint and the shipped
// grants read — grant_type, code, redirect_uri, code_verifier,
// refresh_token, scope, username, password, client_id, client_secret — are
// single-valued (RFC 6749 §3.2): an empty occurrence is omitted, and one
// included more than once with a value is refused with invalid_request
// before the grant runs.
//
// The shipped grants parse a scope parameter like the authorization
// endpoint does (RFC 6749 §3.3, at most 100 tokens and 4096 bytes:
// invalid_scope otherwise) and issue it canonical.
//
// Errors are emitted as JSON: {"error":"...","error_description":"..."}.
func (s *Server) TokenHandler() http.Handler {
	return http.HandlerFunc(s.serveToken)
}

func (s *Server) serveToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeOAuthError(r.Context(), w, ErrInvalidRequest.WithDescription("POST required"))

		return
	}

	if err := s.parseRequestForm(w, r); err != nil {
		s.writeOAuthError(r.Context(), w, formRefusal(err))

		return
	}

	// The client is authenticated at the issuer of the request: one bound
	// to other issuers is unknown here (IssuerBoundClient).
	client, issuer, audience, err := s.authenticateClientAt(r.Context(), r)
	if err != nil {
		s.writeOAuthError(r.Context(), w, err)

		return
	}

	// The token-endpoint parameters are read single-valued, an empty
	// occurrence omitted (RFC 6749 §3.2); one included more than once is
	// refused before the grant runs.
	form, repeated := param.SingleValued(r.PostForm, tokenParameters)
	if repeated != "" {
		s.writeOAuthError(r.Context(), w, repeatedParameter(repeated))

		return
	}

	grantType := form.Get("grant_type")
	if grantType == "" {
		s.writeOAuthError(r.Context(), w, ErrInvalidRequest.WithDescription("missing grant_type"))

		return
	}

	handler, ok := s.dispatch[grantType]
	if !ok {
		s.writeOAuthError(r.Context(), w, ErrUnsupportedGrantType)

		return
	}

	// The client's declaration is checked for every grant type, custom ones
	// included, before the grant runs: a refused request consumes nothing.
	if !ClientAllowsGrantType(client, grantType) {
		s.writeOAuthError(r.Context(), w, grantTypeRefusal(client))

		return
	}

	// One clock read for the whole exchange: the grant stamps the expiry
	// from it, and expires_in is measured against the very same instant, so
	// the advertised lifetime is exactly the configured TTL.
	now := s.cfg.Now()

	resp, err := handler.Handle(r.Context(), GrantRequest{
		Client:    client,
		Form:      form,
		Issuer:    issuer,
		Audience:  audience,
		Now:       now,
		Profile:   s.cfg.Profile,
		Extension: s.cfg.Extension,
	})
	if err != nil {
		s.writeOAuthError(r.Context(), w, err)

		return
	}

	writeTokenResponse(w, resp, now)
}

// errGrantTypeNotDeclared answers a grant type the client does not declare
// (RFC 6749 §5.2 unauthorized_client).
var errGrantTypeNotDeclared = ErrUnauthorizedClient.WithDescription("the client may not use this grant type")

// grantTypeRefusal returns errGrantTypeNotDeclared for c, with
// [ErrNoGrantTypesDeclared] as cause when c declares no grant type at all.
func grantTypeRefusal(c Client) *Error {
	if len(c.GrantTypes()) == 0 {
		return errGrantTypeNotDeclared.WithCause(ErrNoGrantTypesDeclared)
	}

	return errGrantTypeNotDeclared
}

// tokenResponse is the on-wire JSON body per RFC 6749 §5.1. The
// AccessToken / RefreshToken field names are mandated by the RFC; gosec
// flags them under G117 because they look like credentials at rest, but
// here they describe a transient outbound payload.
type tokenResponse struct {
	AccessToken  string `json:"access_token"` //nolint:gosec // wire field name mandated by RFC 6749
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"` //nolint:gosec // wire field name mandated by RFC 6749
	Scope        string `json:"scope,omitempty"`
	// IDToken is the OpenID Connect Core §3.1.3.3 member an Extension adds.
	IDToken string `json:"id_token,omitempty"`
}

// writeTokenResponse serializes resp to the standard JSON body and adds
// Cache-Control / Pragma headers per RFC 6749 §5.1. now is the instant the
// grant was stamped with — the server clock, never the wall clock, so an
// injected [ServerConfig.Now] stays authoritative on the wire too.
func writeTokenResponse(w http.ResponseWriter, resp *GrantResponse, now time.Time) {
	body := tokenResponse{
		AccessToken: resp.Pair.Access.Token,
		TokenType:   resp.TokenType,
		ExpiresIn:   expiresIn(resp.Pair.Access.ExpiresAt, now),
		Scope:       resp.Scope,
		IDToken:     resp.IDToken,
	}

	if resp.Pair.Refresh != nil {
		body.RefreshToken = resp.Pair.Refresh.Token
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)

	//nolint:gosec // G117: token response wire fields are mandated by RFC 6749 §5.1
	if err := json.NewEncoder(w).Encode(body); err != nil {
		// Best-effort: the status code is already on the wire so there's
		// nothing actionable left to do.
		_ = err
	}
}

// expiresIn returns the RFC 6749 §5.1 expires_in value: the token lifetime
// in seconds, rounded to the nearest second so a whole-second TTL is
// advertised as itself rather than one short. An already-expired token
// yields 0 — the field is omitempty, so it drops off the wire instead of
// carrying a negative lifetime the RFC does not allow.
func expiresIn(expiresAt, now time.Time) int {
	d := expiresAt.Sub(now)
	if d <= 0 {
		return 0
	}

	return int(d.Round(time.Second).Seconds())
}

// errorResponse is the on-wire JSON body per RFC 6749 §5.2.
type errorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

// writeOAuthError serializes err as an RFC 6749 §5.2 envelope. Non-OAuth
// errors, and *Error values whose code is malformed, collapse to
// server_error so the wire response stays compliant.
//
// The normalized envelope — cause included — is handed to the configured
// [ErrorHook] before anything is written, since the wire body carries only
// the code, the description and the URI.
func (s *Server) writeOAuthError(ctx context.Context, w http.ResponseWriter, err error) {
	var oe *Error
	if !errors.As(err, &oe) || oe == nil {
		oe = ErrServerError.WithCause(err)
	}

	oe = jsonWireError(oe)

	s.notifyError(ctx, oe)
	writeErrorResponse(w, oe)
}

// writeErrorResponse writes oe as the RFC 6749 §5.2 JSON body, with the
// status code it maps to: a malformed code is answered server_error, and a
// description or error_uri outside the RFC 6749 charset is left out. It
// does not notify the [ErrorHook]: callers that already reported the
// failure behind oe use it directly.
func writeErrorResponse(w http.ResponseWriter, oe *Error) {
	oe = jsonWireError(oe)

	body := errorResponse{
		Error:            oe.Code,
		ErrorDescription: wireDescription(oe.Description),
		ErrorURI:         wireURI(oe.URI),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	if oe.Code == CodeInvalidClient {
		// RFC 6749 §5.2: invalid_client MUST be paired with WWW-Authenticate
		// Basic when the client used HTTP Basic.
		w.Header().Set("WWW-Authenticate", `Basic realm="oauth2"`)
	}

	w.WriteHeader(oe.HTTPStatus())

	if err := json.NewEncoder(w).Encode(body); err != nil {
		_ = err
	}
}
