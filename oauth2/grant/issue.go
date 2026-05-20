// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grant

import (
	"context"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/token"
)

// issueTokenPair mints an access token — and, when the config carries a
// refresh-token generator, a companion refresh token in the same family —
// for the given subject and scope, persists them, and returns the grant
// response. It is the shared issuance path of the authorization_code and
// legacy password grants.
func issueTokenPair(ctx context.Context, cfg Config, req Request, subject, scope string) (*Response, error) {
	familyID, err := newFamilyID()
	if err != nil {
		return nil, oauth2.ErrServerError.WithCause(err)
	}

	expires := req.Now.Add(cfg.AccessTTL)

	atRaw, atHash, err := cfg.AccessTokens.Generate(ctx, token.AccessTokenClaims{
		Issuer:    req.Issuer,
		Subject:   subject,
		Audience:  req.Audience,
		ClientID:  req.Client.ID(),
		Scope:     scope,
		FamilyID:  familyID,
		IssuedAt:  req.Now,
		ExpiresAt: expires,
	})
	if err != nil {
		return nil, oauth2.ErrServerError.WithCause(err)
	}

	access := &oauth2.AccessToken{
		Token: atRaw, TokenHash: atHash, ClientID: req.Client.ID(), Subject: subject,
		Scope: scope, IssuedAt: req.Now, ExpiresAt: expires,
		FamilyID: familyID, Audience: req.Audience,
	}
	if err := cfg.Storage.SaveAccessToken(ctx, access); err != nil {
		return nil, oauth2.ErrServerError.WithCause(err)
	}

	resp := &Response{
		Pair:      oauth2.TokenPair{Access: *access},
		Scope:     scope,
		TokenType: "Bearer",
	}

	if cfg.RefreshTokens == nil {
		return resp, nil
	}

	rtRaw, rtHash, err := cfg.RefreshTokens.Generate(ctx)
	if err != nil {
		return nil, oauth2.ErrServerError.WithCause(err)
	}

	refresh := &oauth2.RefreshToken{
		Token: rtRaw, TokenHash: rtHash, ClientID: req.Client.ID(), Subject: subject,
		Scope: scope, IssuedAt: req.Now, ExpiresAt: req.Now.Add(cfg.RefreshTTL),
		FamilyID: familyID,
	}
	if err := cfg.Storage.SaveRefreshToken(ctx, refresh); err != nil {
		return nil, oauth2.ErrServerError.WithCause(err)
	}

	resp.Pair.Refresh = refresh

	return resp, nil
}
