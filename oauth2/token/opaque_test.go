// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package token_test

import (
	"context"
	"testing"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpaqueGenerateProducesUniqueRandomTokens(t *testing.T) {
	t.Parallel()

	g := token.NewOpaque(32)

	a, ha, err := g.Generate(context.Background(), token.AccessTokenClaims{})
	require.NoError(t, err)
	b, hb, err := g.Generate(context.Background(), token.AccessTokenClaims{})
	require.NoError(t, err)

	assert.NotEqual(t, a, b, "tokens MUST be random")
	assert.NotEqual(t, ha, hb)
	assert.NotEmpty(t, a)
	assert.NotEmpty(t, ha)
}

func TestOpaqueHashMatchesPublicHelper(t *testing.T) {
	t.Parallel()

	g := token.NewOpaque(16)
	tok, hash, err := g.Generate(context.Background(), token.AccessTokenClaims{})
	require.NoError(t, err)

	assert.Equal(t, oauth2.HashToken(nil, tok), hash,
		"the generator's hash MUST match oauth2.HashToken(nil, …) so every lookup path agrees")
}

func TestOpaqueSizeClamps(t *testing.T) {
	t.Parallel()

	g := token.NewOpaque(4) // clamped to 16
	tok, _, err := g.Generate(context.Background(), token.AccessTokenClaims{})
	require.NoError(t, err)
	// base64-url-encoded 16 bytes = 22 chars (no padding).
	assert.Len(t, tok, 22)
}

func TestOpaqueContextCancellation(t *testing.T) {
	t.Parallel()

	g := token.NewOpaque(0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := g.Generate(ctx, token.AccessTokenClaims{})
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestOpaqueRefreshAndCodeAdapters(t *testing.T) {
	t.Parallel()

	g := token.NewOpaque(32)
	r := token.OpaqueRefreshAdapter{Opaque: g}
	c := token.OpaqueCodeAdapter{Opaque: g}

	rt, _, err := r.Generate(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, rt)

	co, _, err := c.Generate(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, co)
}
