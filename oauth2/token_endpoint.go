// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// TokenHandler returns the http.Handler for the RFC 6749 §3.2 /token
// endpoint. The handler:
//
//  1. Enforces POST + application/x-www-form-urlencoded.
//  2. Authenticates the client via the configured ClientAuthenticators.
//  3. Looks up the grant_type and dispatches to the matching Grant.
//  4. Serializes the response per RFC 6749 §5.1 (success) or §5.2 (error).
//
// Errors are emitted as JSON: {"error":"...","error_description":"..."}.
func (s *Server) TokenHandler() http.Handler {
	return http.HandlerFunc(s.serveToken)
}

func (s *Server) serveToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOAuthError(w, ErrInvalidRequest.WithDescription("POST required"))

		return
	}

	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, ErrInvalidRequest.WithCause(err))

		return
	}

	client, err := s.authenticateClient(r.Context(), r)
	if err != nil {
		writeOAuthError(w, err)

		return
	}

	grantType := r.PostFormValue("grant_type")
	if grantType == "" {
		writeOAuthError(w, ErrInvalidRequest.WithDescription("missing grant_type"))

		return
	}

	handler, ok := s.dispatch[grantType]
	if !ok {
		writeOAuthError(w, ErrUnsupportedGrantType.WithDescription("grant_type "+grantType+" not supported"))

		return
	}

	issuer, audience, err := s.resolveIssuer(r.Context(), r)
	if err != nil {
		writeOAuthError(w, err)

		return
	}

	resp, err := handler.Handle(r.Context(), GrantRequest{
		Client:   client,
		Form:     r.PostForm,
		Issuer:   issuer,
		Audience: audience,
		Now:      s.cfg.Now(),
		Profile:  s.cfg.Profile,
	})
	if err != nil {
		writeOAuthError(w, err)

		return
	}

	writeTokenResponse(w, resp)
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
}

// writeTokenResponse serializes resp to the standard JSON body and adds
// Cache-Control / Pragma headers per RFC 6749 §5.1.
func writeTokenResponse(w http.ResponseWriter, resp *GrantResponse) {
	body := tokenResponse{
		AccessToken: resp.Pair.Access.Token,
		TokenType:   resp.TokenType,
		ExpiresIn:   int(time.Until(resp.Pair.Access.ExpiresAt).Seconds()),
		Scope:       resp.Scope,
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

// errorResponse is the on-wire JSON body per RFC 6749 §5.2.
type errorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

// writeOAuthError serializes err as an RFC 6749 §5.2 envelope. Non-OAuth
// errors collapse to server_error so the wire response stays compliant.
func writeOAuthError(w http.ResponseWriter, err error) {
	var oe *Error
	if !errors.As(err, &oe) {
		oe = ErrServerError.WithCause(err)
	}

	body := errorResponse{
		Error:            oe.Code,
		ErrorDescription: oe.Description,
		ErrorURI:         oe.URI,
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
