// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grant

import (
	"context"
	"errors"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/token"
)

// RefreshToken implements RFC 6749 §6 with the OAuth 2.0 BCP §8.10
// hardening (rotation + reuse detection).
//
// The flow:
//
//  1. Look up the refresh token; treat consumed tokens as reuse and revoke
//     the family.
//  2. Re-bind client (refresh.ClientID MUST match the authenticated client).
//  3. Optionally narrow scope (RFC 6749 §6 forbids broadening).
//  4. Issue a fresh access token.
//  5. If RotateRefreshTokens, issue a fresh refresh token in the same
//     family AND atomically mark the old one consumed.
type RefreshToken struct {
	cfg Config
}

// NewRefreshToken constructs the handler.
func NewRefreshToken(cfg Config) *RefreshToken {
	if cfg.Storage == nil || cfg.AccessTokens == nil {
		panic("oauth2/grant: NewRefreshToken requires Storage and AccessTokens")
	}

	return &RefreshToken{cfg: cfg}
}

// Type implements [Grant].
func (g *RefreshToken) Type() string { return "refresh_token" }

// Handle implements [Grant].
func (g *RefreshToken) Handle(ctx context.Context, req Request) (*Response, error) {
	if !grantTypeAllowed(req.Client, "refresh_token") {
		return nil, oauth2.ErrUnauthorizedClient.WithDescription("client cannot use refresh_token")
	}

	raw := req.Form.Get("refresh_token")
	if raw == "" {
		return nil, oauth2.ErrInvalidRequest.WithDescription("missing refresh_token")
	}

	rtHash := oauth2.HashToken(nil, raw)

	rt, err := g.cfg.Storage.LookupRefreshToken(ctx, rtHash)
	if err != nil {
		return nil, err //nolint:wrapcheck // oauth2.* sentinels pass through
	}

	if rt.Consumed {
		// Reuse detected — revoke the whole family and refuse.
		_ = g.cfg.Storage.RevokeRefreshFamily(ctx, rt.FamilyID)

		return nil, oauth2.ErrRefreshTokenReused
	}

	if rt.IsExpired(req.Now) {
		return nil, oauth2.ErrInvalidGrant.WithDescription("refresh_token expired")
	}

	if rt.ClientID != req.Client.ID() {
		return nil, oauth2.ErrInvalidGrant.WithDescription("refresh_token issued for a different client")
	}

	scope, err := narrowScopesForRefresh(req.Form.Get("scope"), rt.Scope)
	if err != nil {
		return nil, err
	}

	return g.issueRotated(ctx, req, rt, scope)
}

func (g *RefreshToken) issueRotated(ctx context.Context, req Request, old *oauth2.RefreshToken, scope string) (*Response, error) {
	expires := req.Now.Add(g.cfg.AccessTTL)

	atRaw, atHash, err := g.cfg.AccessTokens.Generate(ctx, token.AccessTokenClaims{
		Issuer:    req.Issuer,
		Subject:   old.Subject,
		Audience:  req.Audience,
		ClientID:  req.Client.ID(),
		Scope:     scope,
		FamilyID:  old.FamilyID,
		IssuedAt:  req.Now,
		ExpiresAt: expires,
	})
	if err != nil {
		return nil, oauth2.ErrServerError.WithCause(err)
	}

	access := &oauth2.AccessToken{
		Token: atRaw, TokenHash: atHash, ClientID: req.Client.ID(), Subject: old.Subject,
		Scope: scope, IssuedAt: req.Now, ExpiresAt: expires,
		FamilyID: old.FamilyID, Audience: req.Audience,
	}
	if err := g.cfg.Storage.SaveAccessToken(ctx, access); err != nil {
		return nil, oauth2.ErrServerError.WithCause(err)
	}

	resp := &Response{
		Pair:      oauth2.TokenPair{Access: *access},
		Scope:     scope,
		TokenType: oauth2.TokenTypeBearer,
	}

	if !g.cfg.RotateRefreshTokens || g.cfg.RefreshTokens == nil {
		return resp, nil
	}

	rtRaw, rtHash, err := g.cfg.RefreshTokens.Generate(ctx)
	if err != nil {
		return nil, oauth2.ErrServerError.WithCause(err)
	}

	next := &oauth2.RefreshToken{
		Token: rtRaw, TokenHash: rtHash, ClientID: req.Client.ID(), Subject: old.Subject,
		Scope: scope, IssuedAt: req.Now, ExpiresAt: req.Now.Add(g.cfg.RefreshTTL),
		FamilyID: old.FamilyID,
	}

	if err := g.cfg.Storage.RotateRefreshToken(ctx, old.TokenHash, next); err != nil {
		if errors.Is(err, oauth2.ErrRefreshTokenReused) {
			return nil, err //nolint:wrapcheck // oauth2.* sentinels pass through
		}

		return nil, oauth2.ErrServerError.WithCause(err)
	}

	resp.Pair.Refresh = next

	return resp, nil
}

// narrowScopesForRefresh refuses broadening (RFC 6749 §6). An empty
// requested scope inherits the original grant's scope.
func narrowScopesForRefresh(requested, original string) (string, error) {
	if requested == "" {
		return original, nil
	}

	originalSet := make(map[string]struct{}, 8)

	for _, s := range splitScopes(original) {
		originalSet[s] = struct{}{}
	}

	for _, s := range splitScopes(requested) {
		if _, ok := originalSet[s]; !ok {
			return "", oauth2.ErrInvalidScope.WithDescription("refresh cannot broaden scope")
		}
	}

	return requested, nil
}

func splitScopes(s string) []string {
	out := make([]string, 0, 4)
	start := -1

	for i, r := range s {
		if r == ' ' || r == '\t' {
			if start >= 0 {
				out = append(out, s[start:i])
				start = -1
			}

			continue
		}

		if start < 0 {
			start = i
		}
	}

	if start >= 0 {
		out = append(out, s[start:])
	}

	return out
}
