// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package token ships the access-/refresh-/code-token generators used by
// the modular OAuth2 server. Two generator families are provided:
//
//   - Opaque generators emit random strings stored in their hashed form
//     in the storage layer (the default and most secure choice for refresh
//     tokens and authorization codes).
//   - JWT generators emit signed JSON Web Tokens for access tokens, plugged
//     via the jwt sub-module's [jwtsec.Signer].
package token

import (
	"context"
	"time"
)

// AccessTokenClaims is the data passed to access-token generators. The
// struct stays minimal; signers wishing to add custom claims should embed
// it in their own type and project the extra fields in their Sign
// implementation.
type AccessTokenClaims struct {
	// Issuer is the OAuth2 server issuer identifier.
	Issuer string
	// Subject is the resource-owner subject (or client-credentials sub).
	Subject string
	// Audience is the resource server identifier.
	Audience string
	// ClientID is the requesting client identifier.
	ClientID string
	// Scope is the granted scope.
	Scope string
	// FamilyID is the rotation family identifier (refresh-token family).
	FamilyID string
	// IssuedAt is the issuance time.
	IssuedAt time.Time
	// ExpiresAt is the expiry time.
	ExpiresAt time.Time
}

// AccessTokenGenerator produces the wire form of an access token plus the
// storage key (hash) used to look it up. Implementations decide whether
// to emit opaque random strings or signed JWTs.
type AccessTokenGenerator interface {
	// Generate returns the token string handed to the client, the hash to
	// persist in storage, and any error encountered during generation.
	Generate(ctx context.Context, claims AccessTokenClaims) (token, hash string, err error)
}

// RefreshTokenGenerator produces opaque refresh tokens. Refresh tokens are
// ALWAYS opaque (RFC 6749 §1.5 implies it; OAuth 2.0 BCP §8.10 makes it
// explicit) so this interface intentionally has no JWT variant.
type RefreshTokenGenerator interface {
	Generate(ctx context.Context) (token, hash string, err error)
}

// AuthorizationCodeGenerator produces single-use authorization codes.
// Codes are ALWAYS opaque and ALWAYS stored hashed (RFC 6749 §10.5).
type AuthorizationCodeGenerator interface {
	Generate(ctx context.Context) (code, hash string, err error)
}
