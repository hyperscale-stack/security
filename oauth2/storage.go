// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import "context"

// AuthorizationCodeStore persists single-use authorization codes. The
// Consume* operation MUST be atomic: a code may be returned successfully
// to AT MOST one caller.
type AuthorizationCodeStore interface {
	// SaveAuthorizationCode persists the code. The storage layer hashes
	// code.Code into code.CodeHash before persisting.
	SaveAuthorizationCode(ctx context.Context, code *AuthorizationCode) error

	// ConsumeAuthorizationCode atomically reads-and-deletes the code
	// identified by codeHash. Returns [ErrCodeAlreadyUsed] when the code
	// was previously consumed (allowing the server to reject reuse with
	// invalid_grant and revoke the resulting access token per RFC 6749
	// §4.1.2).
	ConsumeAuthorizationCode(ctx context.Context, codeHash string) (*AuthorizationCode, error)
}

// AccessTokenStore persists access tokens. Implementations MUST store hashes
// (the canonical hash function is [HashToken]).
type AccessTokenStore interface {
	SaveAccessToken(ctx context.Context, t *AccessToken) error
	// LookupAccessToken returns the token record matching tokenHash, or
	// nil + ErrInvalidGrant when none matches.
	LookupAccessToken(ctx context.Context, tokenHash string) (*AccessToken, error)
	RevokeAccessToken(ctx context.Context, tokenHash string) error
}

// RefreshTokenStore persists refresh tokens. The rotation operation MUST
// be atomic: rotating a token consumed elsewhere MUST fail with
// [ErrRefreshTokenReused] and trigger family revocation.
type RefreshTokenStore interface {
	SaveRefreshToken(ctx context.Context, t *RefreshToken) error
	// RotateRefreshToken atomically marks oldHash as consumed and persists
	// next as the active refresh token. Returns the new TokenPair on
	// success, ErrRefreshTokenReused when oldHash was already consumed
	// (in which case the implementation MUST also call
	// [RevokeRefreshFamily] for the offending FamilyID before returning).
	RotateRefreshToken(ctx context.Context, oldHash string, next *RefreshToken) error
	// LookupRefreshToken returns the refresh-token record matching
	// tokenHash, or nil + ErrInvalidGrant when none matches. Consumed
	// tokens MUST be returned with Consumed=true so the caller can treat
	// them as reuse.
	LookupRefreshToken(ctx context.Context, tokenHash string) (*RefreshToken, error)
	// RevokeRefreshFamily marks every refresh token in familyID as
	// consumed AND revokes every access token whose FamilyID matches.
	RevokeRefreshFamily(ctx context.Context, familyID string) error
}

// Storage groups the per-aspect interfaces. Implementations MAY decide to
// satisfy individual sub-interfaces with different backends (e.g. SQL for
// authorization codes, Redis for tokens).
type Storage interface {
	AuthorizationCodeStore
	AccessTokenStore
	RefreshTokenStore
}
