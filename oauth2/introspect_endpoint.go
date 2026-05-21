// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"encoding/json"
	"net/http"
)

// IntrospectHandler returns the http.Handler for RFC 7662 token
// introspection. The caller MUST authenticate as an OAuth2 client (the
// same ClientAuthenticators are reused). A successful response carries
// "active":true plus the standard claims; a failed lookup returns
// "active":false with no other fields.
func (s *Server) IntrospectHandler() http.Handler {
	return http.HandlerFunc(s.serveIntrospect)
}

func (s *Server) serveIntrospect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOAuthError(w, ErrInvalidRequest.WithDescription("POST required"))

		return
	}

	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, ErrInvalidRequest.WithCause(err))

		return
	}

	if _, err := s.authenticateClient(r.Context(), r); err != nil {
		writeOAuthError(w, err)

		return
	}

	rawToken := r.PostFormValue("token")
	if rawToken == "" {
		writeOAuthError(w, ErrInvalidRequest.WithDescription("missing token"))

		return
	}

	body := s.introspect(r, rawToken)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(body); err != nil {
		_ = err
	}
}

// introspectResponse is the RFC 7662 §2.2 JSON envelope. We populate the
// most commonly consumed fields; deployments needing custom claims should
// wrap this endpoint.
type introspectResponse struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Subject   string `json:"sub,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Audience  string `json:"aud,omitempty"`
}

func (s *Server) introspect(r *http.Request, rawToken string) introspectResponse {
	hash := HashToken(nil, rawToken)
	now := s.cfg.Now()

	if at, err := s.cfg.Storage.LookupAccessToken(r.Context(), hash); err == nil {
		if at.IsExpired(now) {
			return introspectResponse{Active: false}
		}

		return introspectResponse{
			Active:    true,
			Scope:     at.Scope,
			ClientID:  at.ClientID,
			Subject:   at.Subject,
			ExpiresAt: at.ExpiresAt.Unix(),
			IssuedAt:  at.IssuedAt.Unix(),
			TokenType: TokenTypeBearer,
			Audience:  at.Audience,
		}
	}

	if rt, err := s.cfg.Storage.LookupRefreshToken(r.Context(), hash); err == nil {
		if rt.IsExpired(now) || rt.Consumed {
			return introspectResponse{Active: false}
		}

		return introspectResponse{
			Active:    true,
			Scope:     rt.Scope,
			ClientID:  rt.ClientID,
			Subject:   rt.Subject,
			ExpiresAt: rt.ExpiresAt.Unix(),
			IssuedAt:  rt.IssuedAt.Unix(),
			TokenType: "refresh_token",
		}
	}

	return introspectResponse{Active: false}
}
