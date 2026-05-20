// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// defaultAuthCodeTTL is the authorization-code lifetime applied when
// [AuthorizeConfig.CodeTTL] is left zero (RFC 6749 §4.1.2 recommends a
// maximum of 10 minutes).
const defaultAuthCodeTTL = 10 * time.Minute

// AuthorizeRequest is the parsed and validated /authorize request handed to
// a [ConsentFunc]. By the time the ConsentFunc sees it, the client and the
// redirect URI are already verified.
type AuthorizeRequest struct {
	// Client is the resolved, registered client.
	Client Client
	// ResponseType is the requested response type ("code").
	ResponseType string
	// RedirectURI is the validated redirect URI (exact-matched against the
	// client registration).
	RedirectURI string
	// Scope is the requested scope, already checked against the client's
	// allowed scopes.
	Scope string
	// State is the opaque client state echoed back on the redirect.
	State string
	// CodeChallenge / CodeChallengeMethod carry the PKCE parameters
	// (RFC 7636). Empty when the request carries no PKCE.
	CodeChallenge       string
	CodeChallengeMethod string
	// Nonce echoes the OIDC nonce parameter, when present.
	Nonce string
}

// Consent is the resource-owner decision returned by a [ConsentFunc].
type Consent struct {
	// Approved reports whether the resource owner granted the request.
	Approved bool
	// Subject is the authenticated resource-owner identifier. It is
	// required when Approved is true.
	Subject string
	// Scope is the granted scope. Empty means "exactly what was requested";
	// a non-empty value MUST be a subset of [AuthorizeRequest.Scope] — the
	// consent step may narrow the grant but never broaden it.
	Scope string
}

// ConsentFunc is the application hook invoked by [Server.AuthorizeHandler]
// once the /authorize request is validated. The application authenticates
// the resource owner, renders its own login / consent UI, and returns the
// decision.
//
// Return contract:
//   - (consent, nil): the handler proceeds — it mints the authorization
//     code and redirects to the client's redirect URI.
//   - (nil, nil): the ConsentFunc has already written a response to w
//     (typically the login / consent page on the initial GET); the handler
//     does nothing more.
//   - (nil, err): the handler redirects to the client with a server_error.
type ConsentFunc func(w http.ResponseWriter, r *http.Request, ar *AuthorizeRequest) (*Consent, error)

// AuthorizeConfig configures the /authorize endpoint.
type AuthorizeConfig struct {
	// CodeTTL is the authorization-code lifetime. Defaults to 10 minutes
	// (RFC 6749 §4.1.2) when zero.
	CodeTTL time.Duration
}

// AuthorizeHandler returns the http.Handler for the RFC 6749 §3.1
// authorization endpoint, running the authorization-code flow.
//
// The handler validates the request (client, redirect URI, response type,
// scope, PKCE) and then calls consent. The library owns the protocol
// plumbing — request validation, code minting, the redirect — while the
// application owns the login and consent UI through the [ConsentFunc].
//
// Errors that occur before the redirect URI is trusted (unknown client,
// unregistered redirect URI) are returned directly with a 400 status and
// are NOT redirected, per RFC 6749 §4.1.2.1 (open-redirector protection).
// Every later error is redirected back to the client as an RFC 6749 §4.1.2.1
// error response.
func (s *Server) AuthorizeHandler(cfg AuthorizeConfig, consent ConsentFunc) http.Handler {
	if consent == nil {
		panic("oauth2: AuthorizeHandler: nil ConsentFunc")
	}

	if cfg.CodeTTL <= 0 {
		cfg.CodeTTL = defaultAuthCodeTTL
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.serveAuthorize(cfg, consent, w, r)
	})
}

func (s *Server) serveAuthorize(cfg AuthorizeConfig, consent ConsentFunc, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "oauth2: /authorize requires GET or POST", http.StatusMethodNotAllowed)

		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "oauth2: malformed authorization request", http.StatusBadRequest)

		return
	}

	// Client and redirect URI come first: a failure here MUST NOT redirect
	// (the redirect target is not yet trusted).
	client, err := s.cfg.ClientStore.LoadClient(r.Context(), r.FormValue("client_id"))
	if err != nil || client == nil {
		http.Error(w, "oauth2: unknown or invalid client", http.StatusBadRequest)

		return
	}

	redirectURI, ok := resolveRedirectURI(client, r.FormValue("redirect_uri"))
	if !ok {
		http.Error(w, "oauth2: missing or unregistered redirect_uri", http.StatusBadRequest)

		return
	}

	// From here on the redirect URI is trusted: errors travel back to the
	// client as a redirect.
	ar, oerr := s.parseAuthorizeRequest(r, client, redirectURI)
	if oerr != nil {
		redirectAuthorizeError(w, r, redirectURI, r.FormValue("state"), oerr)

		return
	}

	decision, err := consent(w, r, ar)
	if err != nil {
		redirectAuthorizeError(w, r, redirectURI, ar.State,
			ErrServerError.WithDescription("consent handler failed"))

		return
	}

	if decision == nil {
		// The ConsentFunc rendered its own response (login / consent page).
		return
	}

	if !decision.Approved {
		redirectAuthorizeError(w, r, redirectURI, ar.State,
			ErrAccessDenied.WithDescription("the resource owner denied the request"))

		return
	}

	s.issueAuthorizationCode(cfg, w, r, ar, decision)
}

// parseAuthorizeRequest validates the response type, scope and PKCE
// parameters, returning the [AuthorizeRequest] or an [*Error] to redirect.
func (s *Server) parseAuthorizeRequest(r *http.Request, client Client, redirectURI string) (*AuthorizeRequest, *Error) {
	responseType := r.FormValue("response_type")
	if responseType != "code" {
		return nil, ErrUnsupportedResponseType.WithDescription(
			"response_type " + responseType + " is not supported")
	}

	scope, err := authorizeScope(r.FormValue("scope"), client.Scopes())
	if err != nil {
		return nil, ErrInvalidScope.WithDescription(err.Error())
	}

	challenge := r.FormValue("code_challenge")
	method := r.FormValue("code_challenge_method")

	if err := s.validateAuthorizePKCE(challenge, method); err != nil {
		return nil, ErrInvalidRequest.WithDescription(err.Error())
	}

	return &AuthorizeRequest{
		Client:              client,
		ResponseType:        responseType,
		RedirectURI:         redirectURI,
		Scope:               scope,
		State:               r.FormValue("state"),
		CodeChallenge:       challenge,
		CodeChallengeMethod: method,
		Nonce:               r.FormValue("nonce"),
	}, nil
}

// validateAuthorizePKCE enforces the profile's PKCE policy on the
// /authorize parameters.
func (s *Server) validateAuthorizePKCE(challenge, method string) error {
	if challenge == "" {
		if s.cfg.Profile.RequiresPKCE() {
			return errors.New("code_challenge is required")
		}

		return nil
	}

	switch method {
	case "", "plain":
		if !s.cfg.Profile.AllowsPKCEPlain() {
			return errors.New(`code_challenge_method "plain" is refused by the active profile`)
		}
	case "S256":
		// S256 is always acceptable.
	default:
		return fmt.Errorf("unsupported code_challenge_method %q", method)
	}

	return nil
}

// issueAuthorizationCode mints the code, persists it, and redirects.
func (s *Server) issueAuthorizationCode(
	cfg AuthorizeConfig,
	w http.ResponseWriter,
	r *http.Request,
	ar *AuthorizeRequest,
	decision *Consent,
) {
	granted := ar.Scope

	if decision.Scope != "" {
		// The consent step may narrow the scope but never broaden it.
		narrowed, err := authorizeScope(decision.Scope, strings.Fields(ar.Scope))
		if err != nil {
			redirectAuthorizeError(w, r, ar.RedirectURI, ar.State,
				ErrInvalidScope.WithDescription("granted scope exceeds the request"))

			return
		}

		granted = narrowed
	}

	raw, err := randomCode()
	if err != nil {
		redirectAuthorizeError(w, r, ar.RedirectURI, ar.State, ErrServerError.WithCause(err))

		return
	}

	now := s.cfg.Now()
	// Authorization codes are stored pepper-free (HashToken(nil, …)); the
	// authorization_code grant looks them up the same way.
	code := &AuthorizationCode{
		Code:                raw,
		CodeHash:            HashToken(nil, raw),
		ClientID:            ar.Client.ID(),
		Subject:             decision.Subject,
		RedirectURI:         ar.RedirectURI,
		Scope:               granted,
		CodeChallenge:       ar.CodeChallenge,
		CodeChallengeMethod: ar.CodeChallengeMethod,
		Nonce:               ar.Nonce,
		IssuedAt:            now,
		ExpiresAt:           now.Add(cfg.CodeTTL),
	}

	if err := s.cfg.Storage.SaveAuthorizationCode(r.Context(), code); err != nil {
		redirectAuthorizeError(w, r, ar.RedirectURI, ar.State, ErrServerError.WithCause(err))

		return
	}

	params := url.Values{"code": {raw}}
	if ar.State != "" {
		params.Set("state", ar.State)
	}

	http.Redirect(w, r, appendQuery(ar.RedirectURI, params), http.StatusFound)
}

// resolveRedirectURI returns the redirect URI to use: the requested one
// when it exactly matches a registered URI, or the sole registered URI
// when the request omitted the parameter. RFC 6749 §3.1.2.3 mandates the
// exact match.
func resolveRedirectURI(client Client, requested string) (string, bool) {
	registered := client.RedirectURIs()

	if requested == "" {
		if len(registered) == 1 {
			return registered[0], true
		}

		return "", false
	}

	if slices.Contains(registered, requested) {
		return requested, true
	}

	return "", false
}

// authorizeScope checks that every requested scope is in the allowed set
// and returns the normalized (space-joined) scope. An empty allowed set
// means the client carries no scope restriction.
func authorizeScope(requested string, allowed []string) (string, error) {
	fields := strings.Fields(requested)

	if len(allowed) == 0 {
		return strings.Join(fields, " "), nil
	}

	for _, s := range fields {
		if !slices.Contains(allowed, s) {
			return "", fmt.Errorf("scope %q is not allowed for this client", s)
		}
	}

	return strings.Join(fields, " "), nil
}

// redirectAuthorizeError sends an RFC 6749 §4.1.2.1 error response by
// redirecting back to the client's redirect URI.
func redirectAuthorizeError(w http.ResponseWriter, r *http.Request, redirectURI, state string, oerr *Error) {
	params := url.Values{"error": {oerr.Code}}
	if oerr.Description != "" {
		params.Set("error_description", oerr.Description)
	}

	if state != "" {
		params.Set("state", state)
	}

	http.Redirect(w, r, appendQuery(redirectURI, params), http.StatusFound)
}

// appendQuery merges params into the query string of rawURL.
func appendQuery(rawURL string, params url.Values) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	q := u.Query()

	for k, vs := range params {
		for _, v := range vs {
			q.Set(k, v)
		}
	}

	u.RawQuery = q.Encode()

	return u.String()
}

// randomCode returns a 256-bit base64url authorization code.
func randomCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oauth2: read random: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}
