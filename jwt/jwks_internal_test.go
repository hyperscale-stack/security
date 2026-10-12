// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCurveAlgorithm(t *testing.T) {
	t.Parallel()

	assert.Equal(t, ES256, curveAlgorithm(elliptic.P256()))
	assert.Equal(t, ES384, curveAlgorithm(elliptic.P384()))
	assert.Equal(t, ES512, curveAlgorithm(elliptic.P521()))
	assert.Equal(t, Algorithm(""), curveAlgorithm(elliptic.P224()), "no JWS algorithm for P-224")
}

// refreshingProvider serves an empty set and fails to refresh.
type refreshingProvider struct{ refreshes int }

func (p *refreshingProvider) KeySet(context.Context) (KeySet, error) { return &staticKeySet{}, nil }

func (p *refreshingProvider) refreshKeySet(context.Context) (KeySet, error) {
	p.refreshes++

	return nil, errors.New("upstream down")
}

// TestVerifierReportsRefreshFailures pins that an unknown kid whose
// refresh fails without a usable set is a key set outage, not an invalid
// token.
func TestVerifierReportsRefreshFailures(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signer, err := NewSigner(PrivateKey{KeyID: "k", Algorithm: ES256, Key: priv})
	require.NoError(t, err)

	tok, err := signer.Sign(context.Background(), map[string]any{"sub": "a", "exp": 4102444800})
	require.NoError(t, err)

	p := &refreshingProvider{}

	_, err = NewVerifier(p).Verify(context.Background(), tok, nil)
	require.ErrorIs(t, err, ErrKeySetUnavailable)
	assert.Equal(t, 1, p.refreshes)
}
