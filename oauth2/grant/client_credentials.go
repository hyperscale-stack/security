// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grant

import (
	"context"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/internal/scopes"
	"github.com/hyperscale-stack/security/oauth2/token"
)

// ClientCredentials implements RFC 6749 §4.4: the client authenticates
// itself and obtains an access token bound to its own identity (no
// resource-owner concept).
//
// "The client credentials grant type MUST only be used by confidential
// clients" (RFC 6749 §4.4): a client whose Type is not
// [oauth2.ClientConfidential] — public, or untyped and so not known to be
// confidential — is refused with unauthorized_client, whatever it declares.
// The rule relies on the client authentication the server ran: the shipped
// methods authenticate a confidential client only with its credentials
// (client_secret_basic, client_secret_post; "none" refuses every client
// that is not public), and a custom [oauth2.ClientAuthenticator] MUST NOT
// authenticate a confidential client without one.
//
// Refresh tokens MUST NOT be issued for this grant (RFC 6749 §4.4.3),
// so the handler ignores cfg.RefreshTokens even when set.
type ClientCredentials struct {
	cfg Config
}

// NewClientCredentials constructs the handler.
func NewClientCredentials(cfg Config) *ClientCredentials {
	if cfg.Storage == nil || cfg.AccessTokens == nil {
		panic("oauth2/grant: NewClientCredentials requires Storage and AccessTokens")
	}

	return &ClientCredentials{cfg: cfg}
}

// Type implements [Grant].
func (g *ClientCredentials) Type() string { return oauth2.GrantTypeClientCredentials }

// Handle implements [Grant]. The client has already been authenticated by
// the time the server hands the request to the grant.
func (g *ClientCredentials) Handle(ctx context.Context, req Request) (*Response, error) {
	if req.Client.Type() != oauth2.ClientConfidential {
		return nil, oauth2.ErrUnauthorizedClient.WithDescription("client_credentials requires a confidential client")
	}

	if err := checkGrantType(req.Client, oauth2.GrantTypeClientCredentials); err != nil {
		return nil, err
	}

	scope, err := narrowScopes(req.Form.Get("scope"), req.Client.Scopes())
	if err != nil {
		return nil, err
	}

	expires := req.Now.Add(g.cfg.AccessTTL)

	atRaw, atHash, err := g.cfg.AccessTokens.Generate(ctx, token.AccessTokenClaims{
		Issuer:    req.Issuer,
		Subject:   req.Client.ID(), // sub = client id for machine-to-machine flows
		Audience:  req.Audience,
		ClientID:  req.Client.ID(),
		Scope:     scope,
		IssuedAt:  req.Now,
		ExpiresAt: expires,
	})
	if err != nil {
		return nil, oauth2.ErrServerError.WithCause(err)
	}

	access := &oauth2.AccessToken{
		Token: atRaw, TokenHash: atHash, ClientID: req.Client.ID(), Subject: req.Client.ID(),
		Scope: scope, IssuedAt: req.Now, ExpiresAt: expires, Audience: req.Audience,
		Issuer: req.Issuer,
	}
	// RFC 6749 §4.4.3: no refresh token, and a token outside any family.
	if err := g.cfg.Storage.SaveTokenPair(ctx, &oauth2.TokenPair{Access: *access}); err != nil {
		return nil, oauth2.ErrServerError.WithCause(err)
	}

	return &Response{
		Pair:      oauth2.TokenPair{Access: *access},
		Scope:     scope,
		TokenType: oauth2.TokenTypeBearer,
	}, nil
}

// The descriptions of the scope refusals of the /token grants: fixed texts
// that never echo the request.
const (
	scopeMalformed  = "the requested scope is malformed or too large"
	scopeNotAllowed = "a requested scope is not allowed for this client"
)

// parseRequestedScope parses the scope value a /token request carries:
// RFC 6749 §3.3 syntax, at most 100 tokens and 4096 bytes (see
// oauth2/internal/scopes), else invalid_scope (§5.2 "malformed") with the
// scopes sentinel as cause.
func parseRequestedScope(requested string) ([]string, error) {
	tokens, err := scopes.Parse(requested)
	if err != nil {
		return nil, oauth2.ErrInvalidScope.WithDescription(scopeMalformed).WithCause(err)
	}

	return tokens, nil
}

// narrowScopes checks a requested scope value against the client's allowed
// scopes and returns it canonical: single-SP joined, duplicates dropped.
// Every token must be allowed: a client allowing none can request none
// (invalid_scope, oauth2.ErrNoScopesDeclared as cause). When requested holds
// no scope and the client has at least one, the first one is returned as the
// default — the common UX of "no scope -> default scope" (RFC 6749 §3.3 lets
// the server use a pre-defined default); without any, the scope is empty.
func narrowScopes(requested string, allowed []string) (string, error) {
	tokens, err := parseRequestedScope(requested)
	if err != nil {
		return "", err
	}

	switch {
	case len(tokens) == 0 && len(allowed) > 0:
		return allowed[0], nil
	case !scopes.NewSet(allowed).Admits(tokens):
		refusal := oauth2.ErrInvalidScope.WithDescription(scopeNotAllowed)
		if len(allowed) == 0 {
			refusal = refusal.WithCause(oauth2.ErrNoScopesDeclared)
		}

		return "", refusal
	default:
		return scopes.Join(tokens), nil
	}
}
