// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package token

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/hyperscale-stack/security/oauth2"
)

// Opaque is the generator for opaque (random) access, refresh and
// authorization-code tokens. It writes `size` random bytes (default 32),
// encodes them as base64-url, and hashes the result for storage.
//
// The storage hash is [oauth2.HashToken](nil, token) — an unkeyed SHA-256.
// Opaque tokens carry ≥ 128 bits of entropy, so a bare hash is already
// preimage- and brute-force-resistant; every lookup path (the grants, the
// /introspect and /revoke endpoints) hashes the same way, so a token issued
// here is always found again.
type Opaque struct {
	size int
}

// NewOpaque returns an Opaque generator. size is clamped to 16 bytes
// minimum to provide ~128 bits of entropy even for the smallest tokens;
// 32 bytes (256 bits) is the recommended default and the value used when
// size == 0.
func NewOpaque(size int) *Opaque {
	if size == 0 {
		size = 32
	}

	if size < 16 {
		size = 16
	}

	return &Opaque{size: size}
}

// Generate implements [AccessTokenGenerator]. The claims are ignored — the
// opaque token carries no state; storage holds the AccessToken record.
func (o *Opaque) Generate(ctx context.Context, _ AccessTokenClaims) (string, string, error) {
	return o.generateRaw(ctx)
}

// GenerateRefresh implements [RefreshTokenGenerator] (the Generate(ctx)
// signature with no claims).
func (o *Opaque) GenerateRefresh(ctx context.Context) (string, string, error) {
	return o.generateRaw(ctx)
}

// GenerateCode implements [AuthorizationCodeGenerator].
func (o *Opaque) GenerateCode(ctx context.Context) (string, string, error) {
	return o.generateRaw(ctx)
}

func (o *Opaque) generateRaw(ctx context.Context) (string, string, error) {
	if err := ctx.Err(); err != nil {
		return "", "", fmt.Errorf("oauth2: context canceled: %w", err)
	}

	buf := make([]byte, o.size)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("oauth2: read random: %w", err)
	}

	token := base64.RawURLEncoding.EncodeToString(buf)
	hash := oauth2.HashToken(nil, token)

	return token, hash, nil
}

// OpaqueRefreshAdapter wraps an [Opaque] so it satisfies
// [RefreshTokenGenerator] with the no-claims signature.
type OpaqueRefreshAdapter struct{ *Opaque }

// Generate implements [RefreshTokenGenerator].
func (a OpaqueRefreshAdapter) Generate(ctx context.Context) (string, string, error) {
	return a.GenerateRefresh(ctx)
}

// OpaqueCodeAdapter wraps an [Opaque] so it satisfies
// [AuthorizationCodeGenerator].
type OpaqueCodeAdapter struct{ *Opaque }

// Generate implements [AuthorizationCodeGenerator].
func (a OpaqueCodeAdapter) Generate(ctx context.Context) (string, string, error) {
	return a.GenerateCode(ctx)
}

// Compile-time interface checks.
var (
	_ AccessTokenGenerator       = (*Opaque)(nil)
	_ RefreshTokenGenerator      = OpaqueRefreshAdapter{}
	_ AuthorizationCodeGenerator = OpaqueCodeAdapter{}
)
