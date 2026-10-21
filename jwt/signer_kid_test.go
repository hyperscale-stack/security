// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/cryptosigner"
	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hmacSecret returns a fresh secret of n bytes.
func hmacSecret(t *testing.T, n int) []byte {
	t.Helper()

	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)

	return b
}

// joseHeader returns the decoded JOSE header of a compact JWS.
func joseHeader(t *testing.T, tok string) map[string]any {
	t.Helper()

	raw, err := b64.DecodeString(strings.SplitN(tok, ".", 2)[0])
	require.NoError(t, err)

	var h map[string]any
	require.NoError(t, json.Unmarshal(raw, &h))

	return h
}

// shortClaims are claims every verifier of these tests accepts.
func shortClaims() jwtsec.StandardClaims {
	return jwtsec.StandardClaims{Subject: "alice", ExpiresAt: jwtsec.NewNumericDate(time.Now().Add(time.Hour))}
}

// TestSignerWritesKid pins RFC 7515 §4.1.4 and RFC 7517 §4.5 (audit F-09:
// an HMAC signer wrote no kid, so a verifier holding two HMAC keys could
// not tell which one signed): every signer whose key has a KeyID writes it
// as the "kid" header — HMAC secrets included — and nothing else changes.
func TestSignerWritesKid(t *testing.T) {
	t.Parallel()

	k := newSigningKeys(t)
	ecPriv, _ := genECDSA(t)
	edPriv, _ := genEd25519(t)

	keys := map[string]jwtsec.PrivateKey{
		"HS256":        {KeyID: "hs256-1", Algorithm: jwtsec.HS256, Key: hmacSecret(t, 32)},
		"HS384":        {KeyID: "hs384-1", Algorithm: jwtsec.HS384, Key: hmacSecret(t, 48)},
		"HS512":        {KeyID: "hs512-1", Algorithm: jwtsec.HS512, Key: hmacSecret(t, 64)},
		"RS256":        {KeyID: "rs256-1", Algorithm: jwtsec.RS256, Key: k.rsa2048},
		"PS256":        {KeyID: "ps256-1", Algorithm: jwtsec.PS256, Key: k.rsa2048},
		"ES256":        {KeyID: "es256-1", Algorithm: jwtsec.ES256, Key: ecPriv.Key},
		"EdDSA":        {KeyID: "ed-1", Algorithm: jwtsec.EdDSA, Key: edPriv.Key},
		"opaque RS256": {KeyID: "kms-1", Algorithm: jwtsec.RS256, Key: cryptosigner.Opaque(k.rsa2048)},
	}

	for name, key := range keys {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tok, err := mustSigner(t, key).Sign(context.Background(), shortClaims())
			require.NoError(t, err)
			assert.Equal(t, map[string]any{"alg": string(key.Algorithm), "kid": key.KeyID, "typ": "JWT"}, joseHeader(t, tok))
		})
	}
}

// TestSignerWithoutKeyIDWritesNoKid: a key without KeyID writes no kid
// header — never an empty one.
func TestSignerWithoutKeyIDWritesNoKid(t *testing.T) {
	t.Parallel()

	ecPriv, _ := genECDSA(t)
	ecPriv.KeyID = ""

	for _, key := range []jwtsec.PrivateKey{
		{Algorithm: jwtsec.HS256, Key: hmacSecret(t, 32)},
		ecPriv,
	} {
		tok, err := mustSigner(t, key).Sign(context.Background(), shortClaims())
		require.NoError(t, err)
		assert.NotContains(t, joseHeader(t, tok), "kid", key.Algorithm)
	}
}

// TestHMACKeyRotation pins the consequence of F-09: while two HMAC keys are
// trusted, the tokens of each verify — the kid designates the key — and a
// token of a third key does not.
func TestHMACKeyRotation(t *testing.T) {
	t.Parallel()

	oldKey := jwtsec.PrivateKey{KeyID: "hmac-0", Algorithm: jwtsec.HS256, Key: hmacSecret(t, 32)}
	newKey := jwtsec.PrivateKey{KeyID: "hmac-1", Algorithm: jwtsec.HS256, Key: hmacSecret(t, 32)}
	other := jwtsec.PrivateKey{KeyID: "hmac-2", Algorithm: jwtsec.HS256, Key: hmacSecret(t, 32)}

	trusted := []jwtsec.PublicKey{
		{KeyID: oldKey.KeyID, Algorithm: jwtsec.HS256, Key: oldKey.Key},
		{KeyID: newKey.KeyID, Algorithm: jwtsec.HS256, Key: newKey.Key},
	}

	for _, key := range []jwtsec.PrivateKey{oldKey, newKey} {
		tok, err := mustSigner(t, key).Sign(context.Background(), shortClaims())
		require.NoError(t, err)

		errV, errS := verifyBoth(t, trusted, tok, jwtsec.HS256)
		require.NoError(t, errV, key.KeyID)
		require.NoError(t, errS, key.KeyID)
	}

	tok, err := mustSigner(t, other).Sign(context.Background(), shortClaims())
	require.NoError(t, err)

	errV, errS := verifyBoth(t, trusted, tok, jwtsec.HS256)
	require.ErrorIs(t, errV, jwtsec.ErrInvalidSignature)
	require.ErrorIs(t, errS, jwtsec.ErrInvalidSignature)
}

// TestHMACKidMismatchIsRefused pins the break documented in MIGRATION: a
// verifier whose single HMAC key carries another KeyID than the signer's
// worked while HMAC tokens had no kid; the token now names its key, which
// the verifier does not hold.
func TestHMACKidMismatchIsRefused(t *testing.T) {
	t.Parallel()

	secret := hmacSecret(t, 32)

	tok, err := mustSigner(t, jwtsec.PrivateKey{KeyID: "k", Algorithm: jwtsec.HS256, Key: secret}).
		Sign(context.Background(), shortClaims())
	require.NoError(t, err)

	errV, errS := verifyBoth(t, []jwtsec.PublicKey{{Algorithm: jwtsec.HS256, Key: secret}}, tok, jwtsec.HS256)
	require.ErrorIs(t, errV, jwtsec.ErrInvalidSignature)
	require.ErrorIs(t, errS, jwtsec.ErrInvalidSignature)

	errV, errS = verifyBoth(t, []jwtsec.PublicKey{{KeyID: "k", Algorithm: jwtsec.HS256, Key: secret}}, tok, jwtsec.HS256)
	require.NoError(t, errV, "the signer's KeyID on the verification key")
	require.NoError(t, errS)
}
