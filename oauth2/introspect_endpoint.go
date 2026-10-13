// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/hyperscale-stack/security/oauth2/internal/param"
)

// introspectionCallerRefused describes, to the [ErrorHook], the refusal of
// a caller that is not a confidential client — answered on the wire like
// every failed client authentication.
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
// A token is introspected at the issuer it was issued under only (OpenID
// Connect Core §16.15: issuers are separate realms): at the issuer the
// request resolves to, a token of another issuer — or one recorded without
// issuer, written before tokens recorded one — is not active. An active
// token of that issuer is disclosed — "active":true plus its claims — when
// the [ServerConfig.IntrospectionPolicy] allows it; without a policy, an
// access token is disclosed to every caller, and a refresh token to the
// client it was issued to only (RFC 6749 §1.5: refresh tokens are meant for
// the authorization server). Anything else (an unknown, expired or consumed
// token, one of another issuer, one withheld) answers a bare
// {"active":false} (RFC 7662 §2.2) — so does a token whose lookup failed
// (RFC 7662 §2.1: a server that cannot determine the state of a token
// SHOULD answer it is not active), the failure reported to the
// [ErrorHook].
//
// token and token_type_hint, like the client credentials, are
// single-valued: a request including one more than once with a value is
// answered invalid_request (RFC 6749 §5.2).
func (s *Server) IntrospectHandler() http.Handler {
	return http.HandlerFunc(s.serveIntrospect)
}

func (s *Server) serveIntrospect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeOAuthError(r.Context(), w, ErrInvalidRequest.WithDescription("POST required"))

		return
	}

	if err := s.parseRequestForm(w, r); err != nil {
		s.writeOAuthError(r.Context(), w, formRefusal(err))

		return
	}

	caller, issuer, err := s.authenticateIntrospectionCaller(r.Context(), r)
	if err != nil {
		s.writeOAuthError(r.Context(), w, err)

		return
	}

	// RFC 7662 §2.1: which token a request carrying two would describe is
	// ambiguous.
	form, repeated := param.SingleValued(r.PostForm, tokenLookupParameters)
	if repeated != "" {
		s.writeOAuthError(r.Context(), w, repeatedParameter(repeated))

		return
	}

	rawToken := form.Get("token")
	if rawToken == "" {
		s.writeOAuthError(r.Context(), w, ErrInvalidRequest.WithDescription("missing token"))

		return
	}

	body := s.introspect(r.Context(), caller, issuer, rawToken)

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
// and an untyped client cannot be told apart from one. It returns the
// caller and the issuer the request resolved to.
func (s *Server) authenticateIntrospectionCaller(ctx context.Context, r *http.Request) (Client, string, error) {
	caller, issuer, _, err := s.authenticateClientAt(ctx, r)
	if err != nil {
		return nil, "", err
	}

	if caller.Type() != ClientConfidential {
		return nil, "", clientAuthFailed(ErrInvalidClient.WithDescription(introspectionCallerRefused))
	}

	return caller, issuer, nil
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

// introspect builds the response for rawToken as seen by caller at issuer:
// the claims of an active token it may learn, a bare inactive answer for
// anything else.
func (s *Server) introspect(ctx context.Context, caller Client, issuer, rawToken string) introspectResponse {
	tok, ok := s.lookupActiveToken(ctx, rawToken)
	if !ok || !s.introspectionAllowed(ctx, caller, issuer, tok) {
		return introspectResponse{Active: false}
	}

	return activeIntrospectResponse(tok)
}

// lookupActiveToken resolves rawToken as an access token, then as a
// refresh token, and reports whether it is active: an expired token or a
// consumed refresh token is not, and neither is one whose lookup failed —
// RFC 7662 §2.1: a server unable to determine the state of a token SHOULD
// answer it is not active — the failure reported to the [ErrorHook].
func (s *Server) lookupActiveToken(ctx context.Context, rawToken string) (IntrospectedToken, bool) {
	const what = "introspect: token lookup failed"

	hash := HashToken(nil, rawToken)
	now := s.cfg.Now()

	at, err := s.cfg.Storage.LookupAccessToken(ctx, hash)
	if err == nil {
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

	if !s.lookupMissed(ctx, err, what) {
		return IntrospectedToken{}, false
	}

	rt, err := s.cfg.Storage.LookupRefreshToken(ctx, hash)
	if err == nil {
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

	s.lookupMissed(ctx, err, what)

	return IntrospectedToken{}, false
}

// introspectionAllowed reports whether caller may learn tok at issuer. A
// token of another issuer never: issuers are compared exactly, a token
// recorded without one matching an empty issuer only (OpenID Connect Core
// §16.15, RFC 7662 §4). Then the configured [IntrospectionPolicy] decides;
// without one, every access token is disclosed, and a refresh token to its
// own client only — refresh tokens are meant for the authorization server
// (RFC 6749 §1.5). A failed policy withholds the token — fail closed — and
// is reported to the [ErrorHook], since the response must not tell it apart
// from an unknown token.
func (s *Server) introspectionAllowed(ctx context.Context, caller Client, issuer string, tok IntrospectedToken) bool {
	if tok.Issuer != issuer {
		return false
	}

	if s.cfg.IntrospectionPolicy == nil {
		return tok.Kind != TokenKindRefresh || tok.ClientID == caller.ID()
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
