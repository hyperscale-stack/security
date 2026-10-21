// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPSSVerifierIsBoundToItsAlgorithm (review nit 12): a pssVerifier
// verifies its own algorithm only, whatever its caller checked before — a
// PS256 signature under a PS384-bound verifier, or any algorithm under a
// verifier bound to a non-PSS one, is refused.
func TestPSSVerifierIsBoundToItsAlgorithm(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	msg := []byte("header.payload")
	d := crypto.SHA256.New()
	d.Write(msg)

	sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, d.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	require.NoError(t, err)

	require.NoError(t, pssVerifier{key: &key.PublicKey, alg: PS256}.VerifyPayload(msg, sig, jose.PS256))

	assert.ErrorIs(t, pssVerifier{key: &key.PublicKey, alg: PS384}.VerifyPayload(msg, sig, jose.PS256), errPSSAlgorithm)
	assert.ErrorIs(t, pssVerifier{key: &key.PublicKey, alg: PS256}.VerifyPayload(msg, sig, jose.PS384), errPSSAlgorithm)
	assert.ErrorIs(t, pssVerifier{key: &key.PublicKey, alg: RS256}.VerifyPayload(msg, sig, jose.RS256), errPSSAlgorithm)
}

// TestVerificationKey: PS* RSA keys verify through the strict pssVerifier,
// every other key as itself.
func TestVerificationKey(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	for _, alg := range []Algorithm{PS256, PS384, PS512} {
		assert.Equal(t, pssVerifier{key: &key.PublicKey, alg: alg}, PublicKey{Algorithm: alg, Key: &key.PublicKey}.verificationKey())
	}

	assert.IsType(t, jose.JSONWebKey{}, PublicKey{Algorithm: RS256, Key: &key.PublicKey}.verificationKey())
	assert.IsType(t, jose.JSONWebKey{}, PublicKey{Algorithm: PS256, Key: []byte("not an RSA key")}.verificationKey())
}
