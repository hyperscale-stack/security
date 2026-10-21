// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec_test

import (
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rsaModulus returns an odd integer of exactly bits bits.
func rsaModulus(bits uint) *big.Int {
	n := new(big.Int).Lsh(big.NewInt(1), bits-1)

	return n.Or(n, big.NewInt(1))
}

// rsaPrivateOfBits is an RSA private key whose modulus has bits bits. Its
// values are not a real key — the checks under test only read the sizes —
// which spares generating multi-kilobit primes.
func rsaPrivateOfBits(bits uint) *rsa.PrivateKey {
	return &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: rsaModulus(bits), E: 65537},
		D:         big.NewInt(3),
		Primes:    []*big.Int{big.NewInt(3), big.NewInt(5)},
	}
}

// publicOpaque is an opaque (KMS, HSM) signer whose public half is pub.
// Hand-written like noPublicOpaque and limitedOpaque: go-jose's
// OpaqueSigner is a third-party interface, and a real signer is embedded.
type publicOpaque struct {
	jose.OpaqueSigner

	pub *rsa.PublicKey
}

func (o publicOpaque) Public() *jose.JSONWebKey {
	return &jose.JSONWebKey{Key: o.pub, Algorithm: string(jose.RS256)}
}

// TestSigningKeyRSABound pins the 4096-bit cap of RSA signing keys: the
// JWK Set consumers built on go-jose ≥ v4.1.6 — this package's remote key
// sets and oidc/client included — ignore a larger key, so a token signed
// with one would verify nowhere. NewSigner, NewOAuth2AccessTokenSigner and
// PrivateKey.Validate refuse it at construction, whatever its form (key,
// JWK wrapper, opaque signer); verification keys stay unbounded.
func TestSigningKeyRSABound(t *testing.T) {
	t.Parallel()

	real2048, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	base := cryptosigner.Opaque(real2048)

	assert.NoError(t, jwtsec.PrivateKey{KeyID: "k", Algorithm: jwtsec.RS256, Key: rsaPrivateOfBits(4096)}.Validate(), "4096 bits")
	assert.ErrorIs(t, jwtsec.PrivateKey{KeyID: "k", Algorithm: jwtsec.RS256, Key: rsaPrivateOfBits(4097)}.Validate(), jwtsec.ErrInvalidKey, "4097 bits")

	_, err = jwtsec.PrivateKey{KeyID: "k", Algorithm: jwtsec.PS256, Key: rsaPrivateOfBits(8192)}.Public()
	require.ErrorIs(t, err, jwtsec.ErrInvalidKey)

	refused := map[string]jwtsec.PrivateKey{
		"RSA-4097":          {KeyID: "k", Algorithm: jwtsec.RS256, Key: rsaPrivateOfBits(4097)},
		"RSA-8192, PS512":   {KeyID: "k", Algorithm: jwtsec.PS512, Key: rsaPrivateOfBits(8192)},
		"JWK wrapping 4097": {KeyID: "k", Algorithm: jwtsec.RS256, Key: jose.JSONWebKey{Key: rsaPrivateOfBits(4097)}},
		"opaque, 4097-bit public half": {KeyID: "k", Algorithm: jwtsec.RS256,
			Key: publicOpaque{OpaqueSigner: base, pub: &rsaPrivateOfBits(4097).PublicKey}},
	}

	for name, key := range refused {
		t.Run("refused "+name, func(t *testing.T) {
			t.Parallel()

			s, err := jwtsec.NewSigner(key)
			require.ErrorIs(t, err, jwtsec.ErrInvalidKey)
			assert.Nil(t, s)

			a, err := jwtsec.NewOAuth2AccessTokenSigner(key)
			require.ErrorIs(t, err, jwtsec.ErrInvalidKey)
			assert.Nil(t, a)
		})
	}

	t.Run("accepted opaque, 4096-bit public half", func(t *testing.T) {
		t.Parallel()

		_, err := jwtsec.NewSigner(jwtsec.PrivateKey{KeyID: "k", Algorithm: jwtsec.RS256,
			Key: publicOpaque{OpaqueSigner: base, pub: &rsaPrivateOfBits(4096).PublicKey}})
		require.NoError(t, err)
	})

	t.Run("verification keys unbounded", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, jwtsec.PublicKey{KeyID: "k", Algorithm: jwtsec.RS256, Key: &rsaPrivateOfBits(8192).PublicKey}.Validate())
	})
}

// TestMarshalJWKSRSABound pins that a published JWK Set never holds an RSA
// key over 4096 bits: go-jose ≥ v4.1.6's JSONWebKeySet — go-oidc relying
// parties among others — refuses the whole set when one key is larger, so
// every login of such a relying party would fail. MarshalJWKS refuses it;
// a key of 4096 bits is published.
func TestMarshalJWKSRSABound(t *testing.T) {
	t.Parallel()

	_, err := jwtsec.MarshalJWKS([]jwtsec.PublicKey{{KeyID: "max", Algorithm: jwtsec.RS256, Key: &rsaPrivateOfBits(4096).PublicKey}})
	require.NoError(t, err)

	out, err := jwtsec.MarshalJWKS([]jwtsec.PublicKey{{KeyID: "big", Algorithm: jwtsec.RS256, Key: &rsaPrivateOfBits(4097).PublicKey}})
	require.ErrorIs(t, err, jwtsec.ErrInvalidKey)
	assert.Nil(t, out, "nothing is published")
}
