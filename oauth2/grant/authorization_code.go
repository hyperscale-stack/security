// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grant

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"slices"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/pkce"
	"github.com/hyperscale-stack/security/oauth2/token"
)

// AuthorizationCode implements RFC 6749 §4.1.3 with the RFC 7636 PKCE
// extension. The flow:
//
//  1. Pop the code from storage atomically (single-use enforcement).
//  2. Re-bind client (code.ClientID MUST match the authenticated client).
//  3. Re-bind redirect_uri (RFC 6749 §4.1.3 paragraph 7).
//  4. Verify PKCE when present / required.
//  5. Generate access token (+ optional refresh token).
//  6. Persist both and return the pair.
type AuthorizationCode struct {
	cfg Config
}

// NewAuthorizationCode constructs the handler.
func NewAuthorizationCode(cfg Config) *AuthorizationCode {
	if cfg.Storage == nil || cfg.AccessTokens == nil {
		panic("oauth2/grant: NewAuthorizationCode requires Storage and AccessTokens")
	}

	return &AuthorizationCode{cfg: cfg}
}

// Type implements [Grant].
func (g *AuthorizationCode) Type() string { return "authorization_code" }

// Handle implements [Grant].
func (g *AuthorizationCode) Handle(ctx context.Context, req Request) (*Response, error) {
	rawCode := req.Form.Get("code")
	if rawCode == "" {
		return nil, oauth2.ErrInvalidRequest.WithDescription("missing code")
	}

	hash := oauth2.HashToken(nil, rawCode) // pepper-free: code only lives in storage briefly

	code, err := g.cfg.Storage.ConsumeAuthorizationCode(ctx, hash)
	if err != nil {
		return nil, err //nolint:wrapcheck // oauth2.* sentinels pass through
	}

	if code.IsExpired(req.Now) {
		return nil, oauth2.ErrInvalidGrant.WithDescription("authorization code expired")
	}

	if code.ClientID != req.Client.ID() {
		return nil, oauth2.ErrInvalidGrant.WithDescription("code issued for a different client")
	}

	if redirect := req.Form.Get("redirect_uri"); redirect != code.RedirectURI {
		return nil, oauth2.ErrInvalidGrant.WithDescription("redirect_uri mismatch")
	}

	if err := g.verifyPKCE(req, code); err != nil {
		return nil, err
	}

	if !grantTypeAllowed(req.Client, "authorization_code") {
		return nil, oauth2.ErrUnauthorizedClient.WithDescription("client cannot use authorization_code")
	}

	return g.issueTokens(ctx, req, code)
}

func (g *AuthorizationCode) verifyPKCE(req Request, code *oauth2.AuthorizationCode) error {
	verifier := req.Form.Get("code_verifier")

	if code.CodeChallenge == "" {
		if g.cfg.RequirePKCE {
			return oauth2.ErrInvalidGrant.WithDescription("PKCE required")
		}

		return nil
	}

	if verifier == "" {
		return oauth2.ErrInvalidGrant.WithDescription("missing code_verifier")
	}

	method := pkce.Method(code.CodeChallengeMethod)
	if method == "" {
		method = pkce.MethodPlain
	}

	if !pkce.Verify(method, verifier, code.CodeChallenge) {
		return oauth2.ErrInvalidGrant.WithDescription("PKCE verification failed")
	}

	return nil
}

func (g *AuthorizationCode) issueTokens(ctx context.Context, req Request, code *oauth2.AuthorizationCode) (*Response, error) {
	familyID, err := newFamilyID()
	if err != nil {
		return nil, oauth2.ErrServerError.WithCause(err)
	}

	expires := req.Now.Add(g.cfg.AccessTTL)

	atRaw, atHash, err := g.cfg.AccessTokens.Generate(ctx, token.AccessTokenClaims{
		Issuer:    req.Issuer,
		Subject:   code.Subject,
		Audience:  req.Audience,
		ClientID:  req.Client.ID(),
		Scope:     code.Scope,
		FamilyID:  familyID,
		IssuedAt:  req.Now,
		ExpiresAt: expires,
	})
	if err != nil {
		return nil, oauth2.ErrServerError.WithCause(err)
	}

	access := &oauth2.AccessToken{
		Token: atRaw, TokenHash: atHash, ClientID: req.Client.ID(), Subject: code.Subject,
		Scope: code.Scope, IssuedAt: req.Now, ExpiresAt: expires,
		FamilyID: familyID, Audience: req.Audience,
	}
	if err := g.cfg.Storage.SaveAccessToken(ctx, access); err != nil {
		return nil, oauth2.ErrServerError.WithCause(err)
	}

	resp := &Response{
		Pair:      oauth2.TokenPair{Access: *access},
		Scope:     code.Scope,
		TokenType: "Bearer",
	}

	if g.cfg.RefreshTokens == nil {
		return resp, nil
	}

	rtRaw, rtHash, err := g.cfg.RefreshTokens.Generate(ctx)
	if err != nil {
		return nil, oauth2.ErrServerError.WithCause(err)
	}

	refresh := &oauth2.RefreshToken{
		Token: rtRaw, TokenHash: rtHash, ClientID: req.Client.ID(), Subject: code.Subject,
		Scope: code.Scope, IssuedAt: req.Now, ExpiresAt: req.Now.Add(g.cfg.RefreshTTL),
		FamilyID: familyID,
	}
	if err := g.cfg.Storage.SaveRefreshToken(ctx, refresh); err != nil {
		return nil, oauth2.ErrServerError.WithCause(err)
	}

	resp.Pair.Refresh = refresh

	return resp, nil
}

// grantTypeAllowed reports whether the client is configured for grant.
// An empty GrantTypes() list means "any grant" — common in single-tenant
// deployments where the client list is curated.
func grantTypeAllowed(c oauth2.Client, grant string) bool {
	all := c.GrantTypes()
	if len(all) == 0 {
		return true
	}

	return slices.Contains(all, grant)
}

// newFamilyID returns a 16-byte random identifier used to group every
// access / refresh token issued from the same original authorization.
// base64url -> 22 chars without padding.
func newFamilyID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}
