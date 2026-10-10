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
// refresh-token generator, a companion refresh token — in the family
// familyID for the given subject and scope, persists them atomically, and
// returns the grant response. It is the shared issuance path of the
// authorization_code grant, whose family is derived from the code, and of
// the legacy password grant, whose family is new. A family revoked in the
// meantime — by a replay of the code — refuses the pair with invalid_grant,
// and nothing is issued.
func issueTokenPair(ctx context.Context, cfg Config, req Request, subject, scope, familyID string) (*Response, error) {
	access, err := mintAccess(ctx, cfg, req, subject, scope, familyID)
	if err != nil {
		return nil, err
	}

	pair := &oauth2.TokenPair{Access: *access}

	if cfg.RefreshTokens != nil {
		if pair.Refresh, err = mintRefresh(ctx, cfg, req, subject, scope, familyID); err != nil {
			return nil, err
		}
	}

	if err := cfg.Storage.SaveTokenPair(ctx, pair); err != nil {
		return nil, storageFailure(err)
	}

	return pairResponse(pair, scope), nil
}

// mintAccess generates an access token in familyID; nothing is persisted.
func mintAccess(ctx context.Context, cfg Config, req Request, subject, scope, familyID string) (*oauth2.AccessToken, error) {
	expires := req.Now.Add(cfg.AccessTTL)

	raw, hash, err := cfg.AccessTokens.Generate(ctx, token.AccessTokenClaims{
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

	return &oauth2.AccessToken{
		Token: raw, TokenHash: hash, ClientID: req.Client.ID(), Subject: subject,
		Scope: scope, IssuedAt: req.Now, ExpiresAt: expires,
		FamilyID: familyID, Audience: req.Audience,
	}, nil
}

// mintRefresh generates a refresh token in familyID with the RefreshTokens
// generator, which the caller ensured is set; nothing is persisted.
func mintRefresh(ctx context.Context, cfg Config, req Request, subject, scope, familyID string) (*oauth2.RefreshToken, error) {
	raw, hash, err := cfg.RefreshTokens.Generate(ctx)
	if err != nil {
		return nil, oauth2.ErrServerError.WithCause(err)
	}

	return &oauth2.RefreshToken{
		Token: raw, TokenHash: hash, ClientID: req.Client.ID(), Subject: subject,
		Scope: scope, IssuedAt: req.Now, ExpiresAt: req.Now.Add(cfg.RefreshTTL),
		FamilyID: familyID,
	}, nil
}

// pairResponse wraps a persisted pair into the grant response.
func pairResponse(pair *oauth2.TokenPair, scope string) *Response {
	return &Response{Pair: *pair, Scope: scope, TokenType: oauth2.TokenTypeBearer}
}

// storageFailure maps a failed persistence call to the grant's answer. A
// refusal the store reports as invalid_grant — a revoked family, a refresh
// token that vanished — is the answer RFC 6749 §5.2 prescribes and passes
// through; anything else becomes a server_error whose cause stays off the
// wire.
func storageFailure(err error) error {
	if oauth2.IsCode(err) == oauth2.CodeInvalidGrant {
		return err
	}

	return oauth2.ErrServerError.WithCause(err)
}
