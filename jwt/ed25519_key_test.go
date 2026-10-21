// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// edKey decodes a 32-byte little-endian point encoding given in hex.
func edKey(t *testing.T, s string) ed25519.PublicKey {
	t.Helper()

	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	require.Len(t, b, ed25519.PublicKeySize)

	return b
}

// weakEd25519Keys are the Ed25519 public key encodings no verifier may use
// (RFC 8032 §5.1.3, RFC 8725 §3.4): the 8 points of order dividing 8
// under their canonical encodings, the non-canonical encodings of small-
// order points (y ≥ p, and x = 0 with the sign bit set, §5.1.3 steps 1 and
// 4) — the 14 encodings go-jose refuses in a JWK — and non-canonical
// encodings of large-order points (y ≥ p), which crypto/ed25519 decodes.
var weakEd25519Keys = map[string]string{
	"all zero (y=0, order 4)":        "0000000000000000000000000000000000000000000000000000000000000000",
	"y=0, sign bit (order 4)":        "0000000000000000000000000000000000000000000000000000000000000080",
	"identity (y=1)":                 "0100000000000000000000000000000000000000000000000000000000000000",
	"identity, x=0 with sign bit":    "0100000000000000000000000000000000000000000000000000000000000080",
	"order 8 (a)":                    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	"order 8 (a), sign bit":          "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
	"order 8 (b)":                    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	"order 8 (b), sign bit":          "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
	"order 2 (y=p-1)":                "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"order 2, x=0 with sign bit":     "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"y=p (non-canonical 0)":          "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"y=p, sign bit":                  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"y=p+1 (non-canonical identity)": "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"y=p+1, sign bit":                "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"y=p+3 (non-canonical, order L)": "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"y=p+18 (largest non-canonical)": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"y=p+18, sign bit":               "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
}

// TestEd25519PublicKeyValidation pins audit I-11: PublicKey.Validate
// checked the length of an Ed25519 key only, so a small-order key — an
// all-zero buffer included — was accepted, and a token nobody signed
// verified against it. A small-order or non-canonically encoded key is now
// refused with ErrInvalidKey; a generated key is accepted.
func TestEd25519PublicKeyValidation(t *testing.T) {
	t.Parallel()

	for name, enc := range weakEd25519Keys {
		err := jwtsec.PublicKey{KeyID: "ed", Algorithm: jwtsec.EdDSA, Key: edKey(t, enc)}.Validate()
		require.ErrorIs(t, err, jwtsec.ErrInvalidKey, name)
	}

	// Canonical encodings next to p are accepted — the bound is exact: y =
	// p-2 (p-1 is small order), and a y whose low byte and high byte are
	// those of p but with a middle byte below 0xff.
	for _, enc := range []string{
		"ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"edff00ffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"edfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe7f",
	} {
		assert.NoError(t, jwtsec.PublicKey{Algorithm: jwtsec.EdDSA, Key: edKey(t, enc)}.Validate(), enc)
	}

	for range 1000 {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		require.NoError(t, jwtsec.PublicKey{Algorithm: jwtsec.EdDSA, Key: pub}.Validate())
	}
}

// edForgery returns a token signed by nobody whose signature (R, S)
// verifies against a small-order key A whenever [S]B = R + [k]A holds.
func edForgery(i int, r string, s byte) string {
	input := b64.EncodeToString([]byte(`{"alg":"EdDSA","kid":"ed"}`)) + "." +
		b64.EncodeToString(fmt.Appendf(nil, `{"sub":"mallory","n":%d,"exp":%d}`, i, in(time.Hour)))

	sig, _ := hex.DecodeString(r)
	sig = append(sig, make([]byte, 32)...)
	sig[32] = s

	return input + "." + b64.EncodeToString(sig)
}

// TestEd25519SmallOrderKeyForgeryRefused pins the impact of I-11: with the
// identity key, R = B and S = 1 verify any message; with the all-zero key
// (an uninitialised buffer, order 4), R = identity and S = 0 verify one
// message in four. Every such token is refused — by Verifier and
// VerifySignature alike — and MarshalJWKS refuses to publish the key.
func TestEd25519SmallOrderKeyForgeryRefused(t *testing.T) {
	t.Parallel()

	const (
		basePoint = "5866666666666666666666666666666666666666666666666666666666666666"
		identity  = "0100000000000000000000000000000000000000000000000000000000000000"
	)

	cases := map[string]struct {
		key, r string
		s      byte
	}{
		"identity key":  {identity, basePoint, 1},
		"all-zero key":  {weakEd25519Keys["all zero (y=0, order 4)"], identity, 0},
		"order-8 key":   {weakEd25519Keys["order 8 (a)"], identity, 0},
		"non-canonical": {weakEd25519Keys["y=p+1 (non-canonical identity)"], basePoint, 1},
	}

	for name, tc := range cases {
		keys := []jwtsec.PublicKey{{KeyID: "ed", Algorithm: jwtsec.EdDSA, Key: edKey(t, tc.key)}}

		for i := range 64 {
			errV, errS := verifyBoth(t, keys, edForgery(i, tc.r, tc.s))
			require.ErrorIs(t, errV, jwtsec.ErrInvalidSignature, name)
			require.ErrorIs(t, errV, jwtsec.ErrInvalidKey, name)
			require.ErrorIs(t, errS, jwtsec.ErrInvalidSignature, name)
			require.ErrorIs(t, errS, jwtsec.ErrInvalidKey, name)
		}

		_, err := jwtsec.MarshalJWKS(keys)
		require.ErrorIs(t, err, jwtsec.ErrInvalidKey, name)
	}
}

// TestRemoteJWKSIgnoresWeakEd25519Keys: a JWK Set publishing a small-order
// or non-canonical Ed25519 key has that key ignored (RFC 7517 §5), the
// others used.
func TestRemoteJWKSIgnoresWeakEd25519Keys(t *testing.T) {
	t.Parallel()

	goodPriv, goodPub := genEd25519(t)

	doc := `{"keys":[` +
		fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","kid":"weak","use":"sig","x":%q},`,
			b64.EncodeToString(edKey(t, weakEd25519Keys["y=p+3 (non-canonical, order L)"]))) +
		jwkOf(t, sigKey(goodPub)) + `]}`

	p := newJWKSEndpoint(t, []byte(doc)).provider(t, newTestClock())

	assert.False(t, hasKey(t, p, "weak"), "the non-canonical key is ignored")
	assert.True(t, hasKey(t, p, goodPub.KeyID))

	_, err := jwtsec.NewVerifier(p).Verify(context.Background(), tokenFor(t, goodPriv, goodPub.KeyID), nil)
	require.NoError(t, err)
}

// TestEd25519PrivateKeyConsistency (review finding 3): an ed25519.PrivateKey
// is a seed followed by its public key; one whose second half is not the
// seed's public key — the all-zero 64-byte buffer, whose public half is the
// small-order all-zero point, or two keys spliced together — signs tokens
// that no key verifies. PrivateKey.Public, PrivateKey.Validate and
// NewSigner refuse it with ErrInvalidKey, as they refuse a key of another
// length.
func TestEd25519PrivateKeyConsistency(t *testing.T) {
	t.Parallel()

	_, a, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	_, b, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	spliced := append(append(ed25519.PrivateKey{}, a[:32]...), b[32:]...)

	for name, key := range map[string]ed25519.PrivateKey{
		"all zero":            make(ed25519.PrivateKey, ed25519.PrivateKeySize),
		"seed of another key": spliced,
		"truncated":           a[:31],
		"seed only":           a[:32],
	} {
		priv := jwtsec.PrivateKey{KeyID: "ed", Algorithm: jwtsec.EdDSA, Key: key}

		_, err := priv.Public()
		require.ErrorIs(t, err, jwtsec.ErrInvalidKey, name)
		require.ErrorIs(t, priv.Validate(), jwtsec.ErrInvalidKey, name)

		_, err = jwtsec.NewSigner(priv)
		require.ErrorIs(t, err, jwtsec.ErrInvalidKey, name)
	}

	pub, err := jwtsec.PrivateKey{KeyID: "ed", Algorithm: jwtsec.EdDSA, Key: a}.Public()
	require.NoError(t, err)
	assert.Equal(t, a.Public(), pub.Key)
}
