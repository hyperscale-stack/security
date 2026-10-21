// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fromHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	require.NoError(t, err)

	return b
}

// TestValidEd25519PublicKey checks the Ed25519 key rule: 32 bytes, a
// canonical y (below p, RFC 8032 §5.1.3 step 1), not a point of small order
// — every one of go-jose's weak encodings included — whatever the sign bit.
func TestValidEd25519PublicKey(t *testing.T) {
	t.Parallel()

	refused := map[string]string{
		"y = 0":                       "0000000000000000000000000000000000000000000000000000000000000000",
		"y = 0, sign bit":             "0000000000000000000000000000000000000000000000000000000000000080",
		"identity (y = 1)":            "0100000000000000000000000000000000000000000000000000000000000000",
		"y = 1, sign bit":             "0100000000000000000000000000000000000000000000000000000000000080",
		"order 8 (a)":                 "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"order 8 (a), sign bit":       "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
		"order 8 (b)":                 "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"order 8 (b), sign bit":       "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
		"y = p - 1":                   "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"y = p - 1, sign bit":         "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"y = p (non-canonical 0)":     "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"y = p, sign bit":             "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"y = p + 1 (non-canonical 1)": "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"y = p + 1, sign bit":         "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"y = p + 3 (non-canonical)":   "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"y = p + 3, sign bit":         "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"y = 2^255 - 1":               "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	}

	for name, key := range refused {
		assert.False(t, validEd25519PublicKey(fromHex(t, key)), name)
	}

	for _, n := range []int{0, 31, 33} {
		assert.False(t, validEd25519PublicKey(make([]byte, n)), "length %d", n)
	}

	for range 1000 {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		require.True(t, validEd25519PublicKey(pub), "%x", []byte(pub))
	}
}

// TestCanonicalY checks the y < p boundary byte by byte.
func TestCanonicalY(t *testing.T) {
	t.Parallel()

	cases := map[string]bool{
		"ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f": true,  // p - 2
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f": true,  // p - 1
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f": false, // p
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7e": true,  // below by its top byte
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f7f": true,  // below by a middle byte
		"fffeffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f": true,  // below by its second byte
	}

	for y, want := range cases {
		assert.Equal(t, want, canonicalY(fromHex(t, y)), y)
	}
}

// TestPSSVerifier checks the verifier selection and the defensive branch of
// pssVerifier: PS* keys get the strict verifier, other algorithms their key.
func TestPSSVerifier(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	rsaPub := verificationKey{kind: kindRSA, key: &rsaKey.PublicKey}

	for _, alg := range []Algorithm{PS256, PS384, PS512} {
		assert.Equal(t, pssVerifier{pub: &rsaKey.PublicKey}, rsaPub.verifier(alg), alg)
	}

	for _, alg := range []Algorithm{RS256, RS384, RS512} {
		assert.Same(t, &rsaKey.PublicKey, rsaPub.verifier(alg), alg)
	}

	assert.Same(t, &ecKey.PublicKey, verificationKey{kind: kindEC, key: &ecKey.PublicKey}.verifier(ES256))

	err = pssVerifier{pub: &rsaKey.PublicKey}.VerifyPayload([]byte("input"), make([]byte, 256), jose.RS256)
	require.ErrorIs(t, err, errNotPSS)
}
