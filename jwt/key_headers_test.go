// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// maxRefusalAllocs bounds the allocations of refusing a key-bearing header:
// the strict header decode only. go-jose v4.1.5 validating the advisory key
// of a 16 384-bit prime allocates about 41 000 times.
const maxRefusalAllocs = 1000

// advisoryJWK is the "jwk" member of GHSA-mgcc-cww5-fp2q: an RSA private
// JWK whose p has primeBits bits (n = 2^2048+1, d = q = 3, inconsistent on
// purpose): go-jose v4.1.5 runs rsa.PrivateKey.Validate, cubic in the size
// of p, before any algorithm, key or signature check.
func advisoryJWK(primeBits int) string {
	enc := func(x *big.Int) string { return base64.RawURLEncoding.EncodeToString(x.Bytes()) }

	one := big.NewInt(1)
	n := new(big.Int).Add(new(big.Int).Lsh(one, 2048), one)
	p := new(big.Int).Add(new(big.Int).Lsh(one, uint(primeBits-1)), one)

	return fmt.Sprintf(`{"kty":"RSA","n":%q,"e":"AQAB","d":"Aw","p":%q,"q":"Aw"}`, enc(n), enc(p))
}

// selfSignedDER returns a self-signed certificate of priv's public key.
func selfSignedDER(t *testing.T, priv *ecdsa.PrivateKey) []byte {
	t.Helper()

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "attacker"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)

	return der
}

// refusal is the error text of a header member refused by this package —
// not go-jose's, which says "JWK contains private parameters" since v4.1.6.
func refusal(member string) string {
	return fmt.Sprintf("unsupported %q header parameter", member)
}

// TestVerifyRefusesKeyBearingHeaders pins the local policy that refuses,
// before any go-jose parsing, the JOSE header members that carry or locate
// a key or certificate (RFC 7515 §4.1.2, §4.1.3, §4.1.5, §4.1.6), whatever
// their value: verification keys come from the configured key set only
// (RFC 9068 §4, RFC 7515 §6), a jku or x5u is never followed (RFC 8725
// §3.10), and go-jose parses jwk and x5c before checking anything
// (GHSA-mgcc-cww5-fp2q, audit F-01). Each token is correctly signed by the
// configured key, so the member alone explains the refusal.
func TestVerifyRefusesKeyBearingHeaders(t *testing.T) {
	t.Parallel()

	priv, pub := genECDSA(t)
	keys := []jwtsec.PublicKey{pub}
	payload := fmt.Sprintf(`{"sub":"alice","exp":%d}`, in(time.Hour))

	ecKey, ok := priv.Key.(*ecdsa.PrivateKey)
	require.True(t, ok)

	_, rsaPub := genRSA(t)
	ecJWK := jwkOf(t, jose.JSONWebKey{Key: &ecKey.PublicKey, KeyID: "ec-1", Algorithm: "ES256"})
	rsaJWK := jwkOf(t, jose.JSONWebKey{Key: rsaPub.Key, KeyID: "ec-1", Algorithm: "RS256"})
	cert := base64.StdEncoding.EncodeToString(selfSignedDER(t, ecKey))

	cases := []struct {
		name, member, header string
	}{
		{"jwk of the signing key", "jwk", `{"alg":"ES256","kid":"ec-1","jwk":` + ecJWK + `}`},
		{"jwk of another key", "jwk", `{"alg":"ES256","kid":"ec-1","jwk":` + rsaJWK + `}`},
		{"jwk of the advisory", "jwk", `{"alg":"ES256","kid":"ec-1","jwk":` + advisoryJWK(1024) + `}`},
		{"jwk null", "jwk", `{"alg":"ES256","kid":"ec-1","jwk":null}`},
		{"jwk escaped name", "jwk", `{"alg":"ES256","kid":"ec-1","jwk":` + ecJWK + `}`},
		{"x5c of the signing key", "x5c", `{"alg":"ES256","kid":"ec-1","x5c":["` + cert + `"]}`},
		{"x5c garbage", "x5c", `{"alg":"ES256","kid":"ec-1","x5c":["!!"]}`},
		{"x5c null", "x5c", `{"alg":"ES256","kid":"ec-1","x5c":null}`},
		{"x5c escaped name", "x5c", `{"alg":"ES256","kid":"ec-1","x5c":["` + cert + `"]}`},
		{"jku", "jku", `{"alg":"ES256","kid":"ec-1","jku":"https://attacker.example/jwks"}`},
		{"jku null", "jku", `{"alg":"ES256","kid":"ec-1","jku":null}`},
		{"x5u", "x5u", `{"alg":"ES256","kid":"ec-1","x5u":"https://attacker.example/cert.pem"}`},
		{"x5u null", "x5u", `{"alg":"ES256","kid":"ec-1","x5u":null}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			errV, errS := verifyBoth(t, keys, forge(t, jwtsec.ES256, priv.Key, tc.header, payload))

			for _, err := range []error{errV, errS} {
				require.ErrorIs(t, err, jwtsec.ErrMalformedToken)
				assert.Contains(t, err.Error(), refusal(tc.member), "refused by this package, before go-jose parses the header")
			}
		})
	}

	t.Run("refused before the algorithm allow-list", func(t *testing.T) {
		t.Parallel()

		secret := []byte(strings.Repeat("s", 32))
		h := `{"alg":"HS256","kid":"ec-1","jwk":` + advisoryJWK(1024) + `}`

		errV, errS := verifyBoth(t, keys, forge(t, jwtsec.HS256, secret, h, payload))

		for _, err := range []error{errV, errS} {
			require.ErrorIs(t, err, jwtsec.ErrMalformedToken)
			require.NotErrorIs(t, err, jwtsec.ErrAlgorithmNotAllowed)
			assert.Contains(t, err.Error(), refusal("jwk"))
		}
	})

	t.Run("BearerVerifier", func(t *testing.T) {
		t.Parallel()

		h := `{"alg":"ES256","kid":"ec-1","typ":"at+jwt","jwk":` + advisoryJWK(1024) + `}`
		claims := fmt.Sprintf(`{"iss":%q,"aud":%q,"sub":"alice","client_id":"web","iat":%d,"exp":%d,"jti":"j1"}`,
			rsIssuer, rsAudience, in(0), in(time.Hour))

		_, err := jwtsec.BearerVerifier(rsVerifier(pub), nil).Verify(context.Background(), forge(t, jwtsec.ES256, priv.Key, h, claims))
		require.ErrorIs(t, err, jwtsec.ErrMalformedToken)
		assert.Contains(t, err.Error(), refusal("jwk"))
	})
}

// TestVerifyKeepsThumbprintHeaders pins what stays accepted: the x5t and
// x5t#S256 thumbprints (RFC 7515 §4.1.7, §4.1.8; Entra ID sends x5t), which
// go-jose never parses, and a member whose name differs from jwk only by
// case — another, unknown parameter (RFC 7515 §4: names are case-sensitive)
// that go-jose never parses as a key, so the advisory key under it is
// cheap.
func TestVerifyKeepsThumbprintHeaders(t *testing.T) {
	t.Parallel()

	priv, pub := genECDSA(t)
	keys := []jwtsec.PublicKey{pub}
	payload := fmt.Sprintf(`{"sub":"alice","exp":%d}`, in(time.Hour))
	sha1Print := base64.RawURLEncoding.EncodeToString(make([]byte, 20))
	sha256Print := base64.RawURLEncoding.EncodeToString(make([]byte, 32))

	headers := map[string]string{
		"x5t":                          `{"alg":"ES256","kid":"ec-1","x5t":"` + sha1Print + `"}`,
		"x5t#S256":                     `{"alg":"ES256","kid":"ec-1","x5t#S256":"` + sha256Print + `"}`,
		"JWK holding the advisory key": `{"alg":"ES256","kid":"ec-1","JWK":` + advisoryJWK(16384) + `}`,
	}

	for name, h := range headers {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tok := forge(t, jwtsec.ES256, priv.Key, h, payload)

			errV, errS := verifyBoth(t, keys, tok)
			require.NoError(t, errV)
			require.NoError(t, errS)
		})
	}
}

// TestKeyBearingHeaderRefusedBeforeParsing is the regression test of audit
// F-01 (GHSA-mgcc-cww5-fp2q): the advisory token with a 16 384-bit prime
// (about 2.5 s of CPU and 41 000 allocations per call with go-jose v4.1.5)
// is refused by this package's header check — its error text — at the cost
// of the strict header decode only, through both entry points. A header
// member named JWK, which go-jose leaves alone, stays as cheap. Not
// parallel: AllocsPerRun counts the allocations of every goroutine, and
// parallel tests only start once the sequential ones are done.
func TestKeyBearingHeaderRefusedBeforeParsing(t *testing.T) {
	priv, pub := genECDSA(t)
	keys := []jwtsec.PublicKey{pub}
	v := jwtsec.NewVerifier(jwtsec.NewStaticJWKS(keys))
	payload := fmt.Sprintf(`{"sub":"alice","exp":%d}`, in(time.Hour))
	tok := forge(t, jwtsec.ES256, priv.Key, `{"alg":"ES256","kid":"ec-1","jwk":`+advisoryJWK(16384)+`}`, payload)
	require.LessOrEqual(t, len(tok), jwtsec.DefaultMaxTokenSize, "within the default size bound")

	entryPoints := map[string]func() error{
		"Verifier.Verify": func() error {
			_, err := v.Verify(context.Background(), tok, nil)

			return err
		},
		"VerifySignature": func() error {
			_, err := jwtsec.VerifySignature(context.Background(), tok, keys)

			return err
		},
	}

	for name, verify := range entryPoints {
		var err error

		allocs := testing.AllocsPerRun(1, func() { err = verify() })
		t.Logf("%s: %.0f allocations", name, allocs)

		require.ErrorIs(t, err, jwtsec.ErrMalformedToken, name)
		assert.Contains(t, err.Error(), refusal("jwk"), name)
		assert.NotContains(t, err.Error(), "private parameters", "%s: go-jose never saw the key", name)
		assert.LessOrEqual(t, allocs, float64(maxRefusalAllocs), "%s: refused before go-jose parses the key", name)
	}

	lone := forge(t, jwtsec.ES256, priv.Key, `{"alg":"ES256","kid":"ec-1","JWK":`+advisoryJWK(16384)+`}`, payload)

	var err error

	allocs := testing.AllocsPerRun(1, func() { _, err = v.Verify(context.Background(), lone, nil) })
	t.Logf("JWK member: %.0f allocations", allocs)
	require.NoError(t, err)
	assert.LessOrEqual(t, allocs, float64(maxRefusalAllocs), "a JWK member is never parsed as a key")
}
