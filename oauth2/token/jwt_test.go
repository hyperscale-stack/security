// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package token_test

import (
	"context"
	"errors"
	"testing"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeSigner is a test double for token.AccessTokenSigner.
type fakeSigner struct {
	token string
	err   error
}

func (s fakeSigner) SignAccessToken(context.Context, token.AccessTokenClaims) (string, error) {
	return s.token, s.err
}

func TestNewJWTAccessTokenGeneratorPanicsOnNilSigner(t *testing.T) {
	t.Parallel()

	assert.Panics(t, func() {
		token.NewJWTAccessTokenGenerator(nil)
	})
}

func TestJWTAccessTokenGeneratorGenerate(t *testing.T) {
	t.Parallel()

	gen := token.NewJWTAccessTokenGenerator(fakeSigner{token: "signed.jwt.value"})

	raw, hash, err := gen.Generate(context.Background(), token.AccessTokenClaims{Subject: "alice"})
	require.NoError(t, err)
	assert.Equal(t, "signed.jwt.value", raw)
	// The storage hash is the canonical hash of the raw JWT — the same one
	// every lookup path computes.
	assert.Equal(t, oauth2.HashToken(nil, "signed.jwt.value"), hash)
}

func TestJWTAccessTokenGeneratorSignerError(t *testing.T) {
	t.Parallel()

	gen := token.NewJWTAccessTokenGenerator(fakeSigner{err: errors.New("key unavailable")})

	_, _, err := gen.Generate(context.Background(), token.AccessTokenClaims{})
	require.Error(t, err)
}

func TestJWTAccessTokenGeneratorContextCancelled(t *testing.T) {
	t.Parallel()

	gen := token.NewJWTAccessTokenGenerator(fakeSigner{token: "x"})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := gen.Generate(ctx, token.AccessTokenClaims{})
	require.ErrorIs(t, err, context.Canceled)
}
