// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"math/big"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// privateMembers are the JWK members that carry private or symmetric key
// material (RFC 7518 §6.2.2, §6.3.2, §6.4.1; RFC 8037 §2): a published JWK
// Set holds none of them (OIDC Discovery §3).
var privateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

func TestMarshalJWKSPublishesPublicSignatureKeys(t *testing.T) {
	t.Parallel()

	rsaPriv, rsaPub := genRSA(t)
	_, ecPub := genECDSA(t)
	_, edPub := genEd25519(t)

	raw, err := jwtsec.MarshalJWKS([]jwtsec.PublicKey{rsaPub, ecPub, edPub})
	require.NoError(t, err)

	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(raw, &doc))
	require.Len(t, doc.Keys, 3)

	want := []struct{ kty, kid, alg string }{{"RSA", "rsa-1", "RS256"}, {"EC", "ec-1", "ES256"}, {"OKP", "ed-1", "EdDSA"}}
	for i, w := range want {
		k := doc.Keys[i]
		assert.Equal(t, w.kty, k["kty"])
		assert.Equal(t, w.kid, k["kid"])
		assert.Equal(t, w.alg, k["alg"])
		assert.Equal(t, "sig", k["use"])

		for _, member := range privateMembers {
			assert.NotContains(t, k, member, "%s must not publish %q", w.kid, member)
		}
	}

	assert.Contains(t, doc.Keys[0], "n")
	assert.Contains(t, doc.Keys[0], "e")
	assert.Equal(t, "P-256", doc.Keys[1]["crv"])

	// The set round-trips to the very public keys.
	var set jose.JSONWebKeySet
	require.NoError(t, json.Unmarshal(raw, &set))
	assert.True(t, rsaPriv.Key.(*rsa.PrivateKey).PublicKey.Equal(set.Keys[0].Key))
}

func TestMarshalJWKSRefusesWhatItMustNotPublish(t *testing.T) {
	t.Parallel()

	rsaPriv, rsaPub := genRSA(t)
	ecPriv, ecPub := genECDSA(t)
	edPriv, _ := genEd25519(t)

	small, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	cases := []struct {
		name string
		key  jwtsec.PublicKey
	}{
		{"private RSA key", jwtsec.PublicKey{KeyID: "k", Algorithm: jwtsec.RS256, Key: rsaPriv.Key}},
		{"private EC key", jwtsec.PublicKey{KeyID: "k", Algorithm: jwtsec.ES256, Key: ecPriv.Key}},
		{"private Ed25519 key", jwtsec.PublicKey{KeyID: "k", Algorithm: jwtsec.EdDSA, Key: edPriv.Key}},
		{"symmetric secret", jwtsec.PublicKey{KeyID: "k", Algorithm: jwtsec.HS256, Key: []byte("0123456789abcdef0123456789abcdef")}},
		{"nil key", jwtsec.PublicKey{KeyID: "k", Algorithm: jwtsec.RS256}},
		{"RSA below 2048 bits", jwtsec.PublicKey{KeyID: "k", Algorithm: jwtsec.RS256, Key: &small.PublicKey}},
		{"curve of another algorithm", jwtsec.PublicKey{KeyID: "k", Algorithm: jwtsec.ES256, Key: &p384.PublicKey}},
		{"key of another family", jwtsec.PublicKey{KeyID: "k", Algorithm: jwtsec.ES256, Key: rsaPub.Key}},
		{"RSA key under EdDSA", jwtsec.PublicKey{KeyID: "k", Algorithm: jwtsec.EdDSA, Key: rsaPub.Key}},
		{"no kid", jwtsec.PublicKey{Algorithm: jwtsec.ES256, Key: ecPub.Key}},
		{"no alg", jwtsec.PublicKey{KeyID: "k", Key: ecPub.Key}},
		{"unknown alg", jwtsec.PublicKey{KeyID: "k", Algorithm: "ES999", Key: ecPub.Key}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			out, err := jwtsec.MarshalJWKS([]jwtsec.PublicKey{ecPub, tc.key})
			require.ErrorIs(t, err, jwtsec.ErrInvalidKey)
			assert.Nil(t, out, "nothing is published")
		})
	}

	t.Run("duplicated kid", func(t *testing.T) {
		t.Parallel()

		other := rsaPub
		other.KeyID = ecPub.KeyID

		out, err := jwtsec.MarshalJWKS([]jwtsec.PublicKey{ecPub, other})
		require.ErrorIs(t, err, jwtsec.ErrInvalidKey)
		assert.Nil(t, out)
	})
}

func TestMarshalJWKSOfNoKeysIsAnEmptySet(t *testing.T) {
	t.Parallel()

	raw, err := jwtsec.MarshalJWKS(nil)
	require.NoError(t, err)
	assert.JSONEq(t, `{"keys":[]}`, string(raw))
}

func TestPrivateKeyValidateAndPublic(t *testing.T) {
	t.Parallel()

	for _, gen := range []func(*testing.T) (jwtsec.PrivateKey, jwtsec.PublicKey){genRSA, genECDSA, genEd25519} {
		priv, pub := gen(t)

		require.NoError(t, priv.Validate())
		require.NoError(t, pub.Validate())

		got, err := priv.Public()
		require.NoError(t, err)
		assert.Equal(t, pub.KeyID, got.KeyID)
		assert.Equal(t, pub.Algorithm, got.Algorithm)
		assert.Equal(t, pub.Key, got.Key)
	}

	_, ecPub := genECDSA(t)
	rsaPriv, _ := genRSA(t)

	bad := []jwtsec.PrivateKey{
		{KeyID: "k", Algorithm: jwtsec.RS256, Key: ecPub.Key},                                // a public key
		{KeyID: "k", Algorithm: jwtsec.ES256, Key: rsaPriv.Key},                              // another family
		{KeyID: "k", Algorithm: jwtsec.HS256, Key: []byte("secret-secret-secret-secret-32")}, // symmetric
		{KeyID: "k", Algorithm: jwtsec.RS256},                                                // no key
		{KeyID: "k", Key: rsaPriv.Key},                                                       // no alg
	}

	for i, k := range bad {
		require.ErrorIs(t, k.Validate(), jwtsec.ErrInvalidKey, i)

		_, err := k.Public()
		require.ErrorIs(t, err, jwtsec.ErrInvalidKey, i)
	}
}

// TestKeyValidateBindsECDSACurvesToAlgorithms pins RFC 7518 §3.4: ES256,
// ES384 and ES512 sign on P-256, P-384 and P-521 respectively, and only.
func TestKeyValidateBindsECDSACurvesToAlgorithms(t *testing.T) {
	t.Parallel()

	curves := map[jwtsec.Algorithm]elliptic.Curve{
		jwtsec.ES256: elliptic.P256(), jwtsec.ES384: elliptic.P384(), jwtsec.ES512: elliptic.P521(),
	}

	for alg, curve := range curves {
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)

		for other, otherCurve := range curves {
			pk := jwtsec.PrivateKey{KeyID: "k", Algorithm: other, Key: priv}
			pub := jwtsec.PublicKey{KeyID: "k", Algorithm: other, Key: &priv.PublicKey}

			if otherCurve == curve {
				require.NoError(t, pk.Validate(), alg)
				require.NoError(t, pub.Validate(), alg)

				continue
			}

			require.ErrorIs(t, pk.Validate(), jwtsec.ErrInvalidKey, "%s key under %s", alg, other)
			require.ErrorIs(t, pub.Validate(), jwtsec.ErrInvalidKey, "%s key under %s", alg, other)
		}
	}
}

// TestKeyValidateRefusesMalformedECDSAKeysWithoutPanicking: a key the
// application built badly — no coordinates, no scalar, a point off its
// curve — is refused with ErrInvalidKey; validation never panics.
func TestKeyValidateRefusesMalformedECDSAKeysWithoutPanicking(t *testing.T) {
	t.Parallel()

	good, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	offCurve := good.PublicKey
	offCurve.X = new(big.Int).Add(good.X, big.NewInt(1)) //nolint:staticcheck // SA1019: deliberately invalid test key

	publics := []*ecdsa.PublicKey{
		{Curve: elliptic.P256()},
		{Curve: elliptic.P256(), X: good.X}, //nolint:staticcheck // SA1019: deliberately invalid test key
		&offCurve,
		{X: good.X, Y: good.Y}, //nolint:staticcheck // SA1019: deliberately invalid test key
	}

	for i, pub := range publics {
		require.NotPanics(t, func() {
			err := jwtsec.PublicKey{KeyID: "k", Algorithm: jwtsec.ES256, Key: pub}.Validate()
			require.ErrorIs(t, err, jwtsec.ErrInvalidKey, i)
		})
	}

	privates := []*ecdsa.PrivateKey{
		{PublicKey: good.PublicKey},
		{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()}, D: big.NewInt(1)},
		{PublicKey: good.PublicKey, D: big.NewInt(0)},
	}

	for i, priv := range privates {
		require.NotPanics(t, func() {
			err := jwtsec.PrivateKey{KeyID: "k", Algorithm: jwtsec.ES256, Key: priv}.Validate()
			require.ErrorIs(t, err, jwtsec.ErrInvalidKey, i)
		})
	}
}

func TestPublicKeyValidateRefusesPrivateMaterial(t *testing.T) {
	t.Parallel()

	_, edPub := genEd25519(t)

	short := jwtsec.PublicKey{KeyID: "k", Algorithm: jwtsec.EdDSA, Key: ed25519.PublicKey(edPub.Key.(ed25519.PublicKey)[:16])}
	require.ErrorIs(t, short.Validate(), jwtsec.ErrInvalidKey)
}
