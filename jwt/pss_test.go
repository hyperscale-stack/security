// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec_test

import (
	"context"
	"crypto"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pssHash is the hash of each RSASSA-PSS algorithm (RFC 7518 §3.5).
var pssHash = map[jwtsec.Algorithm]crypto.Hash{
	jwtsec.PS256: crypto.SHA256, jwtsec.PS384: crypto.SHA384, jwtsec.PS512: crypto.SHA512,
}

// maxPSSSalt is the largest salt an RSASSA-PSS signature of key with h can
// carry (RFC 8017 §9.1.1: emLen − hLen − 2, emLen = ⌈(modBits − 1)/8⌉).
func maxPSSSalt(key *rsa.PrivateKey, h crypto.Hash) int {
	return (key.N.BitLen()-1+7)/8 - h.Size() - 2
}

// forgePSS signs header.payload with key under alg with the given salt
// length.
func forgePSS(t *testing.T, alg jwtsec.Algorithm, key *rsa.PrivateKey, salt int) string {
	t.Helper()

	input := b64.EncodeToString([]byte(header(alg, "ps"))) + "." + b64.EncodeToString([]byte(claimsPayload()))
	h := pssHash[alg]

	sig, err := rsa.SignPSS(rand.Reader, key, h, digest(h, []byte(input)), &rsa.PSSOptions{SaltLength: salt})
	require.NoError(t, err)

	return input + "." + b64.EncodeToString(sig)
}

// TestPSSSaltLength pins RFC 7518 §3.5 — "The size of the salt value is the
// same size as the hash function output" (audit I-12: PS256/384/512
// accepted any salt length, go-jose verifying with PSSSaltLengthAuto): a
// signature whose salt is not the hash size is refused, by Verifier and
// VerifySignature alike. A salt of 0 cannot be produced through crypto/rsa
// (SaltLength 0 is PSSSaltLengthAuto, the maximum); 1 and the maximum bound
// the range.
func TestPSSSaltLength(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	for alg, h := range pssHash {
		keys := []jwtsec.PublicKey{{KeyID: "ps", Algorithm: alg, Key: &key.PublicKey}}

		for _, salt := range []int{1, h.Size() - 1, h.Size() + 1, maxPSSSalt(key, h)} {
			errV, errS := verifyBoth(t, keys, forgePSS(t, alg, key, salt))
			require.ErrorIs(t, errV, jwtsec.ErrInvalidSignature, "%s salt %d", alg, salt)
			require.ErrorIs(t, errS, jwtsec.ErrInvalidSignature, "%s salt %d", alg, salt)
		}

		errV, errS := verifyBoth(t, keys, forgePSS(t, alg, key, h.Size()))
		require.NoError(t, errV, "%s with a hash-size salt", alg)
		require.NoError(t, errS, "%s with a hash-size salt", alg)
	}
}

// pssOpaque is an opaque (KMS-style) RSASSA-PSS signer using a fixed salt
// length.
type pssOpaque struct {
	key  *rsa.PrivateKey
	salt int
}

func (o pssOpaque) Public() *jose.JSONWebKey {
	return &jose.JSONWebKey{Key: &o.key.PublicKey}
}

func (o pssOpaque) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{jose.PS256, jose.PS384, jose.PS512}
}

func (o pssOpaque) SignPayload(payload []byte, alg jose.SignatureAlgorithm) ([]byte, error) {
	h := pssHash[jwtsec.Algorithm(alg)]

	sig, err := rsa.SignPSS(rand.Reader, o.key, h, digest(h, payload), &rsa.PSSOptions{SaltLength: o.salt})
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	return sig, nil
}

// TestOpaquePSSSignerSelfCheck pins user decision C2/I-12: the library
// never emits a PS* token it refuses. An opaque signer (KMS, HSM) whose
// salt is not the hash size makes Sign fail with ErrInvalidKey and return
// no token; one using a hash-size salt signs tokens that verify — bare or
// wrapped in a jose.JSONWebKey.
func TestOpaquePSSSignerSelfCheck(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	for alg, h := range pssHash {
		good := pssOpaque{key: key, salt: rsa.PSSSaltLengthEqualsHash}
		bad := pssOpaque{key: key, salt: maxPSSSalt(key, h)}
		pub := []jwtsec.PublicKey{{KeyID: "kms", Algorithm: alg, Key: &key.PublicKey}}

		for name, k := range map[string]any{"bare": good, "JSONWebKey": jose.JSONWebKey{Key: good}, "*JSONWebKey": &jose.JSONWebKey{Key: good}} {
			tok, err := mustSigner(t, jwtsec.PrivateKey{KeyID: "kms", Algorithm: alg, Key: k}).Sign(context.Background(), shortClaims())
			require.NoError(t, err, "%s %s", alg, name)

			errV, errS := verifyBoth(t, pub, tok)
			require.NoError(t, errV, "%s %s", alg, name)
			require.NoError(t, errS, "%s %s", alg, name)
		}

		for name, k := range map[string]any{"bare": bad, "JSONWebKey": jose.JSONWebKey{Key: bad}, "*JSONWebKey": &jose.JSONWebKey{Key: bad}} {
			tok, err := mustSigner(t, jwtsec.PrivateKey{KeyID: "kms", Algorithm: alg, Key: k}).Sign(context.Background(), shortClaims())
			require.ErrorIs(t, err, jwtsec.ErrInvalidKey, "%s %s", alg, name)
			assert.Contains(t, err.Error(), "hash-size PSS salt")
			assert.Empty(t, tok, "no token is returned")
		}
	}
}

// TestCryptosignerPSSIsRefused pins the MIGRATION note: go-jose's
// cryptosigner.Opaque passes PSSSaltLengthAuto, which crypto/rsa signs with
// the maximum salt outside FIPS 140-3 mode — such a PS* signer fails. RS*
// through the same wrapper is unaffected.
func TestCryptosignerPSSIsRefused(t *testing.T) {
	t.Parallel()

	if fips140.Enabled() {
		t.Skip("in FIPS 140-3 mode PSSSaltLengthAuto signs with a hash-size salt")
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	_, err = mustSigner(t, jwtsec.PrivateKey{KeyID: "k", Algorithm: jwtsec.PS256, Key: cryptosigner.Opaque(key)}).
		Sign(context.Background(), shortClaims())
	require.ErrorIs(t, err, jwtsec.ErrInvalidKey)

	_, err = mustSigner(t, jwtsec.PrivateKey{KeyID: "k", Algorithm: jwtsec.RS256, Key: cryptosigner.Opaque(key)}).
		Sign(context.Background(), shortClaims())
	require.NoError(t, err)
}

// TestPSSSignerIsCompliant: an in-process RSA key signs PS* with a
// hash-size salt (go-jose), so its tokens verify under the strict rule.
func TestPSSSignerIsCompliant(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	for alg := range pssHash {
		tok, err := mustSigner(t, jwtsec.PrivateKey{KeyID: "ps", Algorithm: alg, Key: key}).Sign(context.Background(), shortClaims())
		require.NoError(t, err)

		errV, errS := verifyBoth(t, []jwtsec.PublicKey{{KeyID: "ps", Algorithm: alg, Key: &key.PublicKey}}, tok)
		require.NoError(t, errV, alg)
		require.NoError(t, errS, alg)
	}
}
