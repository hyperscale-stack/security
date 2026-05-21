// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grant

import (
	"context"
	"slices"
	"strings"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/token"
)

// ClientCredentials implements RFC 6749 §4.4: the client authenticates
// itself and obtains an access token bound to its own identity (no
// resource-owner concept).
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
func (g *ClientCredentials) Type() string { return "client_credentials" }

// Handle implements [Grant]. The client has already been authenticated by
// the time the server hands the request to the grant.
func (g *ClientCredentials) Handle(ctx context.Context, req Request) (*Response, error) {
	if !grantTypeAllowed(req.Client, "client_credentials") {
		return nil, oauth2.ErrUnauthorizedClient.WithDescription("client cannot use client_credentials")
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
	}
	if err := g.cfg.Storage.SaveAccessToken(ctx, access); err != nil {
		return nil, oauth2.ErrServerError.WithCause(err)
	}

	return &Response{
		Pair:      oauth2.TokenPair{Access: *access},
		Scope:     scope,
		TokenType: oauth2.TokenTypeBearer,
	}, nil
}

// narrowScopes filters requested against the client's allowed scopes. When
// the client has no allowed list, requested is accepted as-is. When
// requested is empty and the client has at least one scope, the first one
// is returned as the default — matches the common UX of "no scope ->
// default scope".
func narrowScopes(requested string, allowed []string) (string, error) {
	requestedFields := strings.Fields(requested)

	if len(allowed) == 0 {
		return requested, nil
	}

	if len(requestedFields) == 0 {
		return allowed[0], nil
	}

	for _, s := range requestedFields {
		if !slices.Contains(allowed, s) {
			return "", oauth2.ErrInvalidScope.WithDescription("scope " + s + " not allowed for client")
		}
	}

	return strings.Join(requestedFields, " "), nil
}
