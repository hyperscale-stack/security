// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grant

import (
	"context"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/token"
)

// issuance describes what one exchange issues: the tokens' subject and
// scopes, the family they join, and the grant context they carry. Every
// token is bound to the request's issuer, which the grant checked against
// the redeemed code or refresh token.
type issuance struct {
	// grantType is the exchange the server's extension extends — an
	// oauth2.GrantType* value — or "" for an exchange it never sees (the
	// legacy password grant).
	grantType string
	// nonce is the nonce the redeemed code recorded; "" on a refresh.
	nonce   string
	subject string
	// scope is the access token's scope.
	scope string
	// refreshScope is the refresh token's scope: the granted scope at a
	// code exchange, the presented token's at a rotation (RFC 6749 §6).
	refreshScope string
	familyID     string
	// extensionData is the grant context of the authorization, copied
	// verbatim onto every token (see oauth2.AuthorizationCode).
	extensionData string
}

// issueTokenPair mints an access token — and, when the config issues one
// for the granted scope, a companion refresh token — for iss, lets the
// server's extension extend the response, persists the pair atomically,
// and returns the grant response. It is the shared issuance path of the
// authorization_code grant, whose family is derived from the code, and of
// the legacy password grant, whose family is new. Nothing is persisted
// before the extension succeeded, and its id_token is only returned with a
// persisted pair. A family revoked in the meantime — by a replay of the
// code — refuses the pair with invalid_grant, and nothing is issued.
func issueTokenPair(ctx context.Context, cfg Config, req Request, iss issuance) (*Response, error) {
	access, err := mintAccess(ctx, cfg, req, iss)
	if err != nil {
		return nil, err
	}

	pair := &oauth2.TokenPair{Access: *access}

	if cfg.issuesRefreshFor(req.Client, iss.refreshScope) {
		if pair.Refresh, err = mintRefresh(ctx, cfg, req, iss); err != nil {
			return nil, err
		}
	}

	idToken, err := extendResponse(ctx, req, iss, pair)
	if err != nil {
		return nil, err
	}

	if err := cfg.Storage.SaveTokenPair(ctx, pair); err != nil {
		return nil, grantFailure(err)
	}

	return pairResponse(pair, iss.scope, idToken), nil
}

// extendResponse runs the server's extension on the exchange iss — when
// the request carries one and the exchange is one it extends — handing it
// the minted, not yet persisted pair: a copy of the access token, and
// whether a refresh token comes with it. It returns the id_token the
// extension adds. A failure is answered through grantFailure.
func extendResponse(ctx context.Context, req Request, iss issuance, pair *oauth2.TokenPair) (string, error) {
	if req.Extension == nil || iss.grantType == "" {
		return "", nil
	}

	ext, err := req.Extension.ExtendTokenResponse(ctx, oauth2.TokenIssuance{
		GrantType:          iss.grantType,
		Client:             req.Client,
		Access:             pair.Access,
		Nonce:              iss.nonce,
		RefreshTokenIssued: pair.Refresh != nil,
	})
	if err != nil {
		return "", grantFailure(err)
	}

	return ext.IDToken, nil
}

// mintAccess generates the access token of iss; nothing is persisted.
func mintAccess(ctx context.Context, cfg Config, req Request, iss issuance) (*oauth2.AccessToken, error) {
	expires := req.Now.Add(cfg.AccessTTL)

	raw, hash, err := cfg.AccessTokens.Generate(ctx, token.AccessTokenClaims{
		Issuer:    req.Issuer,
		Subject:   iss.subject,
		Audience:  req.Audience,
		ClientID:  req.Client.ID(),
		Scope:     iss.scope,
		FamilyID:  iss.familyID,
		IssuedAt:  req.Now,
		ExpiresAt: expires,
	})
	if err != nil {
		return nil, oauth2.ErrServerError.WithCause(err)
	}

	return &oauth2.AccessToken{
		Token: raw, TokenHash: hash, ClientID: req.Client.ID(), Subject: iss.subject,
		Scope: iss.scope, IssuedAt: req.Now, ExpiresAt: expires,
		FamilyID: iss.familyID, Audience: req.Audience,
		Issuer: req.Issuer, ExtensionData: iss.extensionData,
	}, nil
}

// mintRefresh generates the refresh token of iss with the RefreshTokens
// generator, which the caller ensured is set; nothing is persisted.
func mintRefresh(ctx context.Context, cfg Config, req Request, iss issuance) (*oauth2.RefreshToken, error) {
	raw, hash, err := cfg.RefreshTokens.Generate(ctx)
	if err != nil {
		return nil, oauth2.ErrServerError.WithCause(err)
	}

	return &oauth2.RefreshToken{
		Token: raw, TokenHash: hash, ClientID: req.Client.ID(), Subject: iss.subject,
		Scope: iss.refreshScope, IssuedAt: req.Now, ExpiresAt: req.Now.Add(cfg.RefreshTTL),
		FamilyID: iss.familyID, Issuer: req.Issuer, ExtensionData: iss.extensionData,
	}, nil
}

// pairResponse wraps a persisted pair, and the id_token the extension
// added to it, into the grant response.
func pairResponse(pair *oauth2.TokenPair, scope, idToken string) *Response {
	return &Response{Pair: *pair, Scope: scope, TokenType: oauth2.TokenTypeBearer, IDToken: idToken}
}

// grantFailure maps a failed persistence or extension call to the grant's
// answer. A refusal reported as invalid_grant — a revoked family, a refresh
// token that vanished, a grant the extension cannot honor — is the answer
// RFC 6749 §5.2 prescribes and passes through; anything else becomes a
// server_error whose cause stays off the wire.
func grantFailure(err error) error {
	if oauth2.IsCode(err) == oauth2.CodeInvalidGrant {
		return err
	}

	return oauth2.ErrServerError.WithCause(err)
}
