// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/hyperscale-stack/security"
	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func claimsPayload() string {
	return fmt.Sprintf(`{"sub":"alice","exp":%d}`, in(time.Hour))
}

// TestVerifierBindsEachKeyToItsAlgorithm pins RFC 8725 §3.1: "each key MUST
// be used with exactly one algorithm, and this MUST be checked when the
// cryptographic operation is performed" — for the Verifier as for
// VerifySignature (audit JWT-06, probe P2: an RS256 key verified RS384,
// RS512 and PS* tokens).
func TestVerifierBindsEachKeyToItsAlgorithm(t *testing.T) {
	t.Parallel()

	rsaPriv, rsaPub := genRSA(t) // bound to RS256
	keys := []jwtsec.PublicKey{rsaPub}

	for _, alg := range []jwtsec.Algorithm{jwtsec.RS384, jwtsec.RS512, jwtsec.PS256, jwtsec.PS384, jwtsec.PS512} {
		tok := forge(t, alg, rsaPriv.Key, header(alg, "rsa-1"), claimsPayload())

		errV, errS := verifyBoth(t, keys, tok)
		require.ErrorIs(t, errV, jwtsec.ErrInvalidSignature, alg)
		require.ErrorIs(t, errS, jwtsec.ErrInvalidSignature, alg)
		assert.Contains(t, errV.Error(), "another algorithm")
	}

	errV, errS := verifyBoth(t, keys, forge(t, jwtsec.RS256, rsaPriv.Key, header(jwtsec.RS256, "rsa-1"), claimsPayload()))
	require.NoError(t, errV, "the key's own algorithm verifies")
	require.NoError(t, errS)

	// A key without Algorithm verifies nothing.
	unbound := rsaPub
	unbound.Algorithm = ""

	errV, errS = verifyBoth(t, []jwtsec.PublicKey{unbound}, forge(t, jwtsec.RS256, rsaPriv.Key, header(jwtsec.RS256, "rsa-1"), claimsPayload()))
	require.ErrorIs(t, errV, jwtsec.ErrInvalidSignature)
	require.ErrorIs(t, errS, jwtsec.ErrInvalidSignature)

	// An HMAC secret without Algorithm verifies nothing either (only
	// go-jose's length check would remain for it).
	unboundSecret := []byte(strings.Repeat("u", 32))

	errV, errS = verifyBoth(t, []jwtsec.PublicKey{{KeyID: "u", Key: unboundSecret}},
		forge(t, jwtsec.HS256, unboundSecret, header(jwtsec.HS256, "u"), claimsPayload()), jwtsec.HS256)
	require.ErrorIs(t, errV, jwtsec.ErrInvalidSignature)
	require.ErrorIs(t, errS, jwtsec.ErrInvalidSignature)

	// The classic confusion with HS256 allowed: an HMAC secret declared
	// RS256 never verifies an HS256 token (probe P2).
	secret := []byte(strings.Repeat("s", 32))
	declaredRS := jwtsec.PublicKey{KeyID: "k", Algorithm: jwtsec.RS256, Key: secret}

	errV, errS = verifyBoth(t, []jwtsec.PublicKey{declaredRS},
		forge(t, jwtsec.HS256, secret, header(jwtsec.HS256, "k"), claimsPayload()), jwtsec.RS256, jwtsec.HS256)
	require.ErrorIs(t, errV, jwtsec.ErrInvalidSignature)
	require.ErrorIs(t, errS, jwtsec.ErrInvalidSignature)
}

// TestVerifyRejectsKeyConfusion sends the classic HS256 token forged with
// the RSA public key's bytes as the HMAC secret through the Verifier, with
// HS256 allowed: the RSA key is bound to RS256, so it is refused (the
// earlier test never sent such a token).
func TestVerifyRejectsKeyConfusion(t *testing.T) {
	t.Parallel()

	_, rsaPub := genRSA(t)
	der, err := x509.MarshalPKIXPublicKey(rsaPub.Key)
	require.NoError(t, err)

	tok := forge(t, jwtsec.HS256, der, header(jwtsec.HS256, "rsa-1"), claimsPayload())

	for _, keys := range [][]jwtsec.PublicKey{
		{rsaPub},
		{{KeyID: "rsa-1", Algorithm: jwtsec.HS256, Key: rsaPub.Key}}, // an RSA key mislabelled HS256
	} {
		std, err := jwtsec.NewVerifier(jwtsec.NewStaticJWKS(keys), jwtsec.WithAllowedAlgorithms(jwtsec.RS256, jwtsec.HS256)).
			Verify(context.Background(), tok, nil)
		require.ErrorIs(t, err, jwtsec.ErrInvalidSignature)
		assert.Nil(t, std)
	}
}

// TestVerifierRefusesKeysFailingValidate pins RFC 7518 §3.3 ("a key of
// size 2048 bits or larger MUST be used"), §3.4 (the algorithm's curve)
// and the rule that only public keys verify (review F2): a static or
// custom key that PublicKey.Validate refuses verifies nothing, whatever
// its algorithm binding. HMAC keys keep go-jose's RFC 7518 §3.2 length
// check.
func TestVerifierRefusesKeysFailingValidate(t *testing.T) {
	t.Parallel()

	small, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // the point of the test: an undersized key
	require.NoError(t, err)

	big, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cases := []struct {
		name  string
		key   jwtsec.PublicKey
		alg   jwtsec.Algorithm
		sign  any
		allow []jwtsec.Algorithm
	}{
		{"RSA-1024", jwtsec.PublicKey{KeyID: "k", Algorithm: jwtsec.RS256, Key: &small.PublicKey}, jwtsec.RS256, small, nil},
		{"private RSA key as PublicKey", jwtsec.PublicKey{KeyID: "k", Algorithm: jwtsec.RS256, Key: big}, jwtsec.RS256, big, nil},
		{"jose.JSONWebKey wrapper", jwtsec.PublicKey{KeyID: "k", Algorithm: jwtsec.RS256, Key: jose.JSONWebKey{Key: &big.PublicKey}}, jwtsec.RS256, big, nil},
		{"P-256 key bound to ES384", jwtsec.PublicKey{KeyID: "k", Algorithm: jwtsec.ES384, Key: &p256.PublicKey}, jwtsec.ES384, p256, nil},
		{"private EC key as PublicKey", jwtsec.PublicKey{KeyID: "k", Algorithm: jwtsec.ES256, Key: p256}, jwtsec.ES256, p256, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tok := forge(t, tc.alg, tc.sign, header(tc.alg, "k"), claimsPayload())

			errV, errS := verifyBoth(t, []jwtsec.PublicKey{tc.key}, tok, tc.allow...)
			for _, err := range []error{errV, errS} {
				require.ErrorIs(t, err, jwtsec.ErrInvalidSignature)
				require.ErrorIs(t, err, jwtsec.ErrInvalidKey)
				require.ErrorIs(t, err, security.ErrInvalidCredentials)
			}
		})
	}

	// A short HMAC secret is refused by go-jose (RFC 7518 §3.2).
	short := []byte("0123456789abcdef")
	errV, errS := verifyBoth(t, []jwtsec.PublicKey{{KeyID: "h", Algorithm: jwtsec.HS256, Key: short}},
		forge(t, jwtsec.HS256, short, header(jwtsec.HS256, "h"), claimsPayload()), jwtsec.HS256)
	require.ErrorIs(t, errV, jwtsec.ErrInvalidSignature)
	require.ErrorIs(t, errS, jwtsec.ErrInvalidSignature)

	// A long-enough HMAC secret bound to HS256 verifies.
	long := []byte(strings.Repeat("k", 32))
	errV, errS = verifyBoth(t, []jwtsec.PublicKey{{KeyID: "h", Algorithm: jwtsec.HS256, Key: long}},
		forge(t, jwtsec.HS256, long, header(jwtsec.HS256, "h"), claimsPayload()), jwtsec.HS256)
	require.NoError(t, errV)
	require.NoError(t, errS)
}

// TestVerifierRefusesAmbiguousKids pins RFC 7515 §4.1.4 / RFC 7517 §4.5: a
// kid shared by several keys designates none, and a token without kid is
// verified only against a single-key set.
func TestVerifierRefusesAmbiguousKids(t *testing.T) {
	t.Parallel()

	priv, pub := genECDSA(t)
	_, other := genECDSA(t) // same kid "ec-1", another key

	withKid := forge(t, jwtsec.ES256, priv.Key, header(jwtsec.ES256, "ec-1"), claimsPayload())
	noKid := forge(t, jwtsec.ES256, priv.Key, `{"alg":"ES256"}`, claimsPayload())

	errV, errS := verifyBoth(t, []jwtsec.PublicKey{other, pub}, withKid)
	require.ErrorIs(t, errV, jwtsec.ErrInvalidSignature, "a duplicated kid designates no key")
	require.ErrorIs(t, errS, jwtsec.ErrInvalidSignature)

	kidless := pub
	kidless.KeyID = ""

	_, rsaPub := genRSA(t)

	for _, keys := range [][]jwtsec.PublicKey{{pub, rsaPub}, {kidless, rsaPub}} {
		errV, errS = verifyBoth(t, keys, noKid)
		require.ErrorIs(t, errV, jwtsec.ErrInvalidSignature, "no kid among several keys")
		require.ErrorIs(t, errS, jwtsec.ErrInvalidSignature)
	}

	errV, errS = verifyBoth(t, []jwtsec.PublicKey{pub}, noKid)
	require.NoError(t, errV, "no kid against a single-key set")
	require.NoError(t, errS)

	set, err := jwtsec.NewStaticJWKS([]jwtsec.PublicKey{other, pub}).KeySet(context.Background())
	require.NoError(t, err)

	_, ok := set.ByKeyID("ec-1")
	assert.False(t, ok, "ByKeyID refuses an ambiguous kid")
}
