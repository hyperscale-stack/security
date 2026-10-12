// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// jwkOf marshals a JWK.
func jwkOf(t *testing.T, k jose.JSONWebKey) string {
	t.Helper()

	b, err := json.Marshal(k)
	require.NoError(t, err)

	return string(b)
}

// withMember adds a member to a marshalled JWK.
func withMember(jwk, member string) string { return strings.TrimSuffix(jwk, "}") + "," + member + "}" }

// TestRemoteJWKSValidatesEachKey pins RFC 7517 §5 ("implementations SHOULD
// ignore JWKs … that use kty values that are not understood …, that are
// missing required members, or for which values are out of the supported
// ranges"), §4.2-§4.3 (use, key_ops), RFC 7518 §3.3 (RSA ≥ 2048 bits),
// §6 (private and symmetric members) and decision 8 (per-key validation;
// audit JWT-09, probes R5-R9 and the unknown-kty probe): an unusable key
// is ignored alone — the set is never poisoned — and an RSA key without
// alg follows the OpenID Connect rule (review F7).
func TestRemoteJWKSValidatesEachKey(t *testing.T) {
	t.Parallel()

	goodPriv, goodPub := ecKey(t, "good")
	goodJWK := jwkOf(t, sigKey(goodPub))

	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // the point of the test: an undersized key
	require.NoError(t, err)

	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	secret := []byte(strings.Repeat("s", 32))

	// An 8200-bit RSA modulus (no private key needed: it is never used).
	bigN := new(big.Int).Lsh(big.NewInt(1), 8199)
	bigN.Or(bigN, big.NewInt(1))
	bigRSA := `{"kty":"RSA","kid":"big","alg":"RS256","use":"sig","n":"` + base64.RawURLEncoding.EncodeToString(bigN.Bytes()) + `","e":"AQAB"}`

	rsaKid := func(kid, alg string, pub any) string {
		return jwkOf(t, jose.JSONWebKey{Key: pub, KeyID: kid, Algorithm: alg, Use: "sig"})
	}

	type tokenCase struct {
		alg      jwtsec.Algorithm
		key      any
		accepted bool
	}

	cases := []struct {
		name    string
		jwks    []string
		kid     string
		present bool // the key is in the set
		allowed []jwtsec.Algorithm
		tokens  []tokenCase
	}{
		{"oct key, HS256 allowed", []string{jwkOf(t, jose.JSONWebKey{Key: secret, KeyID: "x", Algorithm: "HS256", Use: "sig"})}, "x", false,
			[]jwtsec.Algorithm{jwtsec.ES256, jwtsec.HS256}, []tokenCase{{jwtsec.HS256, secret, false}}},
		{"RSA-1024", []string{rsaKid("x", "RS256", &rsa1024.PublicKey)}, "x", false, nil,
			[]tokenCase{{jwtsec.RS256, rsa1024, false}}},
		{"RSA over 8192 bits", []string{bigRSA}, "big", false, nil, nil},
		{"EC key declaring RS256", []string{rsaKid("x", "RS256", &p256.PublicKey)}, "x", false, nil,
			[]tokenCase{{jwtsec.ES256, p256, false}}},
		{"RSA key bound to RS256, token PS512", []string{rsaKid("x", "RS256", &rsa2048.PublicKey)}, "x", true, nil,
			[]tokenCase{{jwtsec.PS512, rsa2048, false}, {jwtsec.RS256, rsa2048, true}}},
		{"key_ops without verify", []string{withMember(jwkOf(t, jose.JSONWebKey{Key: &p256.PublicKey, KeyID: "x", Algorithm: "ES256"}), `"key_ops":["encrypt"]`)}, "x", false, nil,
			[]tokenCase{{jwtsec.ES256, p256, false}}},
		{"key_ops with verify", []string{withMember(jwkOf(t, jose.JSONWebKey{Key: &p256.PublicKey, KeyID: "x", Algorithm: "ES256"}), `"key_ops":["sign","verify"]`)}, "x", true, nil,
			[]tokenCase{{jwtsec.ES256, p256, true}}},
		{"key_ops not an array", []string{withMember(jwkOf(t, jose.JSONWebKey{Key: &p256.PublicKey, KeyID: "x", Algorithm: "ES256"}), `"key_ops":"verify"`)}, "x", false, nil, nil},
		{"use enc", []string{jwkOf(t, jose.JSONWebKey{Key: &p256.PublicKey, KeyID: "x", Algorithm: "ES256", Use: "enc"})}, "x", false, nil,
			[]tokenCase{{jwtsec.ES256, p256, false}}},
		{"use not a string", []string{withMember(jwkOf(t, jose.JSONWebKey{Key: &p256.PublicKey, KeyID: "x", Algorithm: "ES256"}), `"use":1`)}, "x", false, nil, nil},
		{"private RSA key published", []string{rsaKid("x", "RS256", rsa2048)}, "x", false, nil,
			[]tokenCase{{jwtsec.RS256, rsa2048, false}}},
		{"private EC key published", []string{jwkOf(t, jose.JSONWebKey{Key: p256, KeyID: "x", Algorithm: "ES256", Use: "sig"})}, "x", false, nil, nil},
		// A public key publishing a prime: go-jose parses it as public, yet
		// anyone can derive its private exponent.
		{"RSA key leaking a prime", []string{withMember(rsaKid("x", "RS256", &rsa2048.PublicKey),
			`"p":"`+base64.RawURLEncoding.EncodeToString(rsa2048.Primes[0].Bytes())+`"`)}, "x", false, nil,
			[]tokenCase{{jwtsec.RS256, rsa2048, false}}},
		{"EC key with a k member", []string{withMember(jwkOf(t, jose.JSONWebKey{Key: &p256.PublicKey, KeyID: "x", Algorithm: "ES256", Use: "sig"}), `"k":"AAAA"`)}, "x", false, nil, nil},
		{"duplicate kid", []string{rsaKid("x", "RS256", &rsa2048.PublicKey), jwkOf(t, jose.JSONWebKey{Key: &p256.PublicKey, KeyID: "x", Algorithm: "ES256", Use: "sig"})}, "x", false, nil,
			[]tokenCase{{jwtsec.RS256, rsa2048, false}, {jwtsec.ES256, p256, false}}},
		{"alg none", []string{jwkOf(t, jose.JSONWebKey{Key: &p256.PublicKey, KeyID: "x", Algorithm: "none", Use: "sig"})}, "x", false, nil, nil},
		{"alg-less RSA, RS256 allowed", []string{rsaKid("x", "", &rsa2048.PublicKey)}, "x", true, nil,
			[]tokenCase{{jwtsec.RS256, rsa2048, true}, {jwtsec.PS256, rsa2048, false}}},
		{"alg-less RSA, PS256 the only RSA algorithm", []string{rsaKid("x", "", &rsa2048.PublicKey)}, "x", true,
			[]jwtsec.Algorithm{jwtsec.ES256, jwtsec.PS256}, []tokenCase{{jwtsec.PS256, rsa2048, true}}},
		{"alg-less RSA, two RSA algorithms but not RS256", []string{rsaKid("x", "", &rsa2048.PublicKey)}, "x", true,
			[]jwtsec.Algorithm{jwtsec.ES256, jwtsec.PS256, jwtsec.PS384}, []tokenCase{{jwtsec.PS256, rsa2048, false}, {jwtsec.PS384, rsa2048, false}}},
		{"alg-less RSA-1024", []string{rsaKid("x", "", &rsa1024.PublicKey)}, "x", false, nil, nil},
		{"alg-less P-384", []string{jwkOf(t, jose.JSONWebKey{Key: &p384.PublicKey, KeyID: "x", Use: "sig"})}, "x", true, nil,
			[]tokenCase{{jwtsec.ES384, p384, true}, {jwtsec.ES256, p384, false}}},
		{"alg-less Ed25519", []string{jwkOf(t, jose.JSONWebKey{Key: edPub, KeyID: "x", Use: "sig"})}, "x", true, nil,
			[]tokenCase{{jwtsec.EdDSA, edPriv, true}}},
		{"X25519 encryption key", []string{`{"kty":"OKP","crv":"X25519","use":"enc","kid":"x","x":"hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"}`}, "x", false, nil, nil},
		{"ML-DSA key (AKP)", []string{`{"kty":"AKP","alg":"ML-DSA-44","kid":"x","pub":"AAAA"}`}, "x", false, nil, nil},
		{"secp256k1 key", []string{`{"kty":"EC","crv":"secp256k1","alg":"ES256K","kid":"x","x":"AAAA","y":"AAAA"}`}, "x", false, nil, nil},
		{"Ed448 key", []string{`{"kty":"OKP","crv":"Ed448","kid":"x","x":"AAAA"}`}, "x", false, nil, nil},
		{"unknown kty", []string{`{"kty":"XYZ","kid":"x"}`}, "x", false, nil, nil},
		{"malformed RSA key", []string{`{"kty":"RSA","kid":"x","n":"!!","e":"AQAB"}`}, "x", false, nil, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			doc := `{"keys":[` + goodJWK + `,` + strings.Join(tc.jwks, ",") + `]}`
			e := newJWKSEndpoint(t, []byte(doc))
			p := e.provider(t, newTestClock())

			var opts []jwtsec.Option
			if tc.allowed != nil {
				opts = append(opts, jwtsec.WithAllowedAlgorithms(tc.allowed...))
			}

			v := jwtsec.NewVerifier(p, opts...)

			_, err := v.Verify(context.Background(), tokenFor(t, goodPriv, "good"), nil)
			require.NoError(t, err, "the other keys of the set stay usable")

			assert.Equal(t, tc.present, hasKey(t, p, tc.kid))

			for _, tok := range tc.tokens {
				_, err := v.Verify(context.Background(), forge(t, tok.alg, tok.key, header(tok.alg, tc.kid), claimsPayload()), nil)
				if tok.accepted {
					require.NoError(t, err, tok.alg)
				} else {
					require.Error(t, err, tok.alg)
					assert.NotErrorIs(t, err, jwtsec.ErrKeySetUnavailable, tok.alg)
				}
			}
		})
	}
}
