// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package token

import (
	"context"
	"fmt"

	"github.com/hyperscale-stack/security/oauth2"
)

// AccessTokenSigner is the contract a JWT signer must satisfy to plug into
// the OAuth2 server as an access-token generator. It deliberately mirrors
// [jwtsec.Signer.Sign] but keeps the OAuth2 module free of a hard dependency
// on the JWT sub-module: callers wire the dependency in their composition
// root via [JWTAccessTokenGenerator].
type AccessTokenSigner interface {
	// SignAccessToken signs the supplied AccessTokenClaims and returns the
	// resulting compact-JWS string. Implementations are responsible for
	// projecting the claims onto the JWT structure they want to emit
	// (e.g. the RFC 9068 "JWT Profile for OAuth 2.0 Access Tokens").
	SignAccessToken(ctx context.Context, claims AccessTokenClaims) (string, error)
}

// JWTAccessTokenGenerator adapts an [AccessTokenSigner] to the
// [AccessTokenGenerator] interface consumed by the OAuth2 server. The
// storage-lookup hash is [oauth2.HashToken](nil, token), so revocation and
// introspection locate the AccessToken record without persisting the raw
// JWT (the JWS is large; storing only the hash keeps the table compact and
// removes the leak window). Every lookup path hashes the same way.
type JWTAccessTokenGenerator struct {
	signer AccessTokenSigner
}

// NewJWTAccessTokenGenerator wraps signer into an [AccessTokenGenerator].
func NewJWTAccessTokenGenerator(signer AccessTokenSigner) *JWTAccessTokenGenerator {
	if signer == nil {
		panic("oauth2/token.NewJWTAccessTokenGenerator: nil AccessTokenSigner")
	}

	return &JWTAccessTokenGenerator{signer: signer}
}

// Generate implements [AccessTokenGenerator]. It delegates the JWS
// generation to the signer and computes the storage hash on the result.
func (g *JWTAccessTokenGenerator) Generate(ctx context.Context, claims AccessTokenClaims) (string, string, error) {
	if err := ctx.Err(); err != nil {
		return "", "", fmt.Errorf("oauth2: context canceled: %w", err)
	}

	token, err := g.signer.SignAccessToken(ctx, claims)
	if err != nil {
		return "", "", fmt.Errorf("oauth2: sign access token: %w", err)
	}

	return token, oauth2.HashToken(nil, token), nil
}

// Compile-time interface check.
var _ AccessTokenGenerator = (*JWTAccessTokenGenerator)(nil)
