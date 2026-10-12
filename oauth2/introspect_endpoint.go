// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"context"
	"encoding/json"
	"net/http"
)

// introspectionCallerRefused is the error_description of the 401 answered
// to a caller that is not a confidential client. It stays within the
// RFC 6749 §5.2 charset.
const introspectionCallerRefused = "introspection requires confidential client authentication"

// IntrospectHandler returns the http.Handler for RFC 7662 token
// introspection.
//
// Only confidential clients are answered. RFC 7662 §2.1 and §4 require the
// endpoint to authenticate the protected resources calling it, and a public
// client cannot authenticate: its client_id is no secret, and no credential
// it presents can be relied on to identify it (RFC 6749 §2.2, §2.3). The
// caller authenticates through the configured [ServerConfig.ClientAuth]
// methods at the issuer the request resolves to — one bound to other
// issuers is unknown there ([IssuerBoundClient]) — and must be a
// [ClientConfidential] client; a public client —
// whatever the method, "none" included — or an untyped one gets 401
// invalid_client.
//
// An active token is disclosed — "active":true plus its claims — when the
// [ServerConfig.IntrospectionPolicy] allows it, or when no policy is set.
// Anything else (an unknown, expired or consumed token, or one the policy
// withholds) answers a bare {"active":false} (RFC 7662 §2.2).
func (s *Server) IntrospectHandler() http.Handler {
	return http.HandlerFunc(s.serveIntrospect)
}

func (s *Server) serveIntrospect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeOAuthError(r.Context(), w, ErrInvalidRequest.WithDescription("POST required"))

		return
	}

	if err := r.ParseForm(); err != nil {
		s.writeOAuthError(r.Context(), w, ErrInvalidRequest.WithCause(err))

		return
	}

	caller, err := s.authenticateIntrospectionCaller(r.Context(), r)
	if err != nil {
		s.writeOAuthError(r.Context(), w, err)

		return
	}

	rawToken := r.PostFormValue("token")
	if rawToken == "" {
		s.writeOAuthError(r.Context(), w, ErrInvalidRequest.WithDescription("missing token"))

		return
	}

	body := s.introspect(r.Context(), caller, rawToken)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(body); err != nil {
		_ = err
	}
}

// authenticateIntrospectionCaller authenticates the caller through the
// shared client-authentication chain, then admits confidential clients
// only: a public client's credentials prove nothing (RFC 6749 §2.2, §2.3),
// and an untyped client cannot be told apart from one.
func (s *Server) authenticateIntrospectionCaller(ctx context.Context, r *http.Request) (Client, error) {
	caller, _, _, err := s.authenticateClientAt(ctx, r)
	if err != nil {
		return nil, err
	}

	if caller.Type() != ClientConfidential {
		return nil, ErrInvalidClient.WithDescription(introspectionCallerRefused)
	}

	return caller, nil
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

// introspect builds the response for rawToken as seen by caller: the
// claims of an active token the policy discloses, a bare inactive answer
// for anything else.
func (s *Server) introspect(ctx context.Context, caller Client, rawToken string) introspectResponse {
	tok, ok := s.lookupActiveToken(ctx, rawToken)
	if !ok || !s.introspectionAllowed(ctx, caller, tok) {
		return introspectResponse{Active: false}
	}

	return activeIntrospectResponse(tok)
}

// lookupActiveToken resolves rawToken as an access token, then as a
// refresh token, and reports whether it is active: an expired token or a
// consumed refresh token is not.
func (s *Server) lookupActiveToken(ctx context.Context, rawToken string) (IntrospectedToken, bool) {
	hash := HashToken(nil, rawToken)
	now := s.cfg.Now()

	if at, err := s.cfg.Storage.LookupAccessToken(ctx, hash); err == nil {
		if at.IsExpired(now) {
			return IntrospectedToken{}, false
		}

		return IntrospectedToken{
			Kind:      TokenKindAccess,
			ClientID:  at.ClientID,
			Subject:   at.Subject,
			Scope:     at.Scope,
			Audience:  at.Audience,
			Issuer:    at.Issuer,
			IssuedAt:  at.IssuedAt,
			ExpiresAt: at.ExpiresAt,
		}, true
	}

	if rt, err := s.cfg.Storage.LookupRefreshToken(ctx, hash); err == nil {
		if rt.IsExpired(now) || rt.Consumed {
			return IntrospectedToken{}, false
		}

		return IntrospectedToken{
			Kind:      TokenKindRefresh,
			ClientID:  rt.ClientID,
			Subject:   rt.Subject,
			Scope:     rt.Scope,
			Issuer:    rt.Issuer,
			IssuedAt:  rt.IssuedAt,
			ExpiresAt: rt.ExpiresAt,
		}, true
	}

	return IntrospectedToken{}, false
}

// introspectionAllowed runs the configured [IntrospectionPolicy]; without
// one, every confidential caller may see every token. A failed policy
// withholds the token — fail closed — and is reported to the [ErrorHook],
// since the response must not tell it apart from an unknown token.
func (s *Server) introspectionAllowed(ctx context.Context, caller Client, tok IntrospectedToken) bool {
	if s.cfg.IntrospectionPolicy == nil {
		return true
	}

	allowed, err := s.cfg.IntrospectionPolicy(ctx, caller, tok)
	if err != nil {
		s.notifyError(ctx, ErrServerError.WithDescription("introspection policy failed").WithCause(err))

		return false
	}

	return allowed
}

// activeIntrospectResponse renders an active token as the RFC 7662 §2.2
// body.
func activeIntrospectResponse(tok IntrospectedToken) introspectResponse {
	tokenType := TokenTypeBearer
	if tok.Kind == TokenKindRefresh {
		// RFC 6749 §5.1 defines no "refresh_token" token type; the value is
		// kept so a resource server can tell a refresh token apart and
		// refuse it.
		tokenType = string(TokenKindRefresh)
	}

	return introspectResponse{
		Active:    true,
		Scope:     tok.Scope,
		ClientID:  tok.ClientID,
		Subject:   tok.Subject,
		ExpiresAt: tok.ExpiresAt.Unix(),
		IssuedAt:  tok.IssuedAt.Unix(),
		TokenType: tokenType,
		Audience:  tok.Audience,
	}
}
