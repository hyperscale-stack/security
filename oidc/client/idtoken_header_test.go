// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/hyperscale-stack/security"
	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rawJWS signs the verbatim JOSE header and payload with the fake OP's
// published RS256 key (kid rsa-1): JSON a go-jose signer would never write.
func rawJWS(t *testing.T, rawHeader string, payload []byte) string {
	t.Helper()
	loadKeys()

	input := base64.RawURLEncoding.EncodeToString([]byte(rawHeader)) + "." + base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(input))

	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaA, crypto.SHA256, sum[:])
	require.NoError(t, err)

	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// withRawHeader makes the OP issue its ID Token under the verbatim header.
func withRawHeader(header string) func(op *fakeOP) {
	return func(op *fakeOP) {
		op.idTokenHook = func(g *grant) string {
			payload, err := json.Marshal(op.idClaims(g))
			require.NoError(op.t, err)

			return rawJWS(op.t, header, payload)
		}
	}
}

// advisoryJWK is the "jwk" member of GHSA-mgcc-cww5-fp2q: an RSA private
// JWK whose p has primeBits bits (n = 2^2048+1, d = q = 3, inconsistent on
// purpose), which go-jose v4.1.5 validated — at a cost cubic in the size of
// p — before any check.
func advisoryJWK(primeBits int) string {
	enc := func(x *big.Int) string { return base64.RawURLEncoding.EncodeToString(x.Bytes()) }

	one := big.NewInt(1)
	n := new(big.Int).Add(new(big.Int).Lsh(one, 2048), one)
	p := new(big.Int).Add(new(big.Int).Lsh(one, uint(primeBits-1)), one)

	return fmt.Sprintf(`{"kty":"RSA","n":%q,"e":"AQAB","d":"Aw","p":%q,"q":"Aw"}`, enc(n), enc(p))
}

// headerLogin runs a login whose ID Token carries the verbatim header.
func headerLogin(t *testing.T, header string) (*oidcclient.Identity, error) {
	t.Helper()

	op := newFakeOP(t)
	op.set(withRawHeader(header))

	return op.login(t, op.client(t))
}

// TestIDTokenKeyBearingHeaders pins the refusal, before go-jose parses the
// ID Token, of the JOSE header members that carry or locate a key or
// certificate (RFC 7515 §4.1.2, §4.1.3, §4.1.5, §4.1.6), whatever their
// value: OpenID Connect Core §2 (ID Tokens SHOULD NOT use them) and
// §3.1.3.7 (the client MUST use the keys provided by the issuer) — a local
// policy where RFC 7515 §4 would ignore them; go-jose parses jwk and x5c
// before any check (GHSA-mgcc-cww5-fp2q, audit F-02). Each token is signed
// by the published key: the member alone explains the refusal, and its
// text shows the package refused it, not go-jose.
func TestIDTokenKeyBearingHeaders(t *testing.T) {
	t.Parallel()

	loadKeys()

	evilJWK, err := json.Marshal(jose.JSONWebKey{Key: &rsaEvil.PublicKey, KeyID: "rsa-1", Algorithm: "RS256"})
	require.NoError(t, err)

	cases := []struct {
		name, member, header string
	}{
		{"jwk of the attacker", "jwk", `{"alg":"RS256","kid":"rsa-1","jwk":` + string(evilJWK) + `}`},
		{"jwk of the advisory", "jwk", `{"alg":"RS256","kid":"rsa-1","jwk":` + advisoryJWK(16384) + `}`},
		{"jwk null", "jwk", `{"alg":"RS256","kid":"rsa-1","jwk":null}`},
		{"jwk escaped name", "jwk", `{"alg":"RS256","kid":"rsa-1","\u006awk":` + string(evilJWK) + `}`},
		{"jwk with HS256", "jwk", `{"alg":"HS256","kid":"rsa-1","jwk":` + advisoryJWK(1024) + `}`},
		{"x5c", "x5c", `{"alg":"RS256","kid":"rsa-1","x5c":["MIIB"]}`},
		{"x5c null", "x5c", `{"alg":"RS256","kid":"rsa-1","x5c":null}`},
		{"x5c escaped name", "x5c", `{"alg":"RS256","kid":"rsa-1","x5\u0063":["MIIB"]}`},
		{"jku", "jku", `{"alg":"RS256","kid":"rsa-1","jku":"https://attacker.example/jwks"}`},
		{"jku null", "jku", `{"alg":"RS256","kid":"rsa-1","jku":null}`},
		{"jku escaped name", "jku", `{"alg":"RS256","kid":"rsa-1","j\u006bu":"https://attacker.example/jwks"}`},
		{"x5u", "x5u", `{"alg":"RS256","kid":"rsa-1","x5u":"https://attacker.example/cert.pem"}`},
		{"x5u null", "x5u", `{"alg":"RS256","kid":"rsa-1","x5u":null}`},
		{"x5u escaped name", "x5u", `{"alg":"RS256","kid":"rsa-1","x5\u0075":"https://attacker.example/cert.pem"}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if strings.Contains(tc.name, "escaped") {
				require.Contains(t, tc.header, `\u00`, "the member name is written with a JSON escape")
			}

			id, err := headerLogin(t, tc.header)
			require.ErrorIs(t, err, oidcclient.ErrIDTokenMalformed)
			require.ErrorIs(t, err, security.ErrInvalidCredentials)
			require.NotErrorIs(t, err, oidcclient.ErrIDTokenAlgorithm, "refused before the algorithm allow-list")
			assert.Nil(t, id)
			assert.Contains(t, err.Error(), fmt.Sprintf("unsupported %q header parameter", tc.member), "refused by the package")
			assert.NotContains(t, err.Error(), "private parameters", "go-jose never saw the key")
		})
	}
}

// TestIDTokenThumbprintAndUnknownHeaders pins what stays accepted: x5t and
// x5t#S256 (RFC 7515 §4.1.7, §4.1.8; Entra ID sends x5t), and a lone member
// whose name differs from jwk or typ only by case — another, unknown
// parameter (RFC 7515 §4: names are case-sensitive), ignored, which go-jose
// never parses as a key.
func TestIDTokenThumbprintAndUnknownHeaders(t *testing.T) {
	t.Parallel()

	sha1Print := base64.RawURLEncoding.EncodeToString(make([]byte, 20))
	sha256Print := base64.RawURLEncoding.EncodeToString(make([]byte, 32))

	headers := map[string]string{
		"x5t":               `{"alg":"RS256","kid":"rsa-1","typ":"JWT","x5t":"` + sha1Print + `"}`,
		"x5t#S256":          `{"alg":"RS256","kid":"rsa-1","typ":"JWT","x5t#S256":"` + sha256Print + `"}`,
		"lone JWK":          `{"alg":"RS256","kid":"rsa-1","JWK":` + advisoryJWK(16384) + `}`,
		"lone TYP":          `{"alg":"RS256","kid":"rsa-1","TYP":"at+jwt"}`,
		"control, no extra": `{"alg":"RS256","kid":"rsa-1","typ":"JWT"}`,
	}

	for name, h := range headers {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			id, err := headerLogin(t, h)
			require.NoError(t, err)
			assert.Equal(t, testSubject, id.Subject)
		})
	}
}

// TestIDTokenHeaderStrict pins the strict decoding of the JOSE header
// (audit I-15; RFC 7515 §4: parameter names are unique; RFC 7519 §7.2 step
// 4; RFC 8725 §3.7): duplicate names — exact, escaped or differing only by
// case — invalid UTF-8, unpaired surrogates and anything but one object are
// refused before go-jose decodes the header, so no decoder can read another
// typ or alg than the one checked. The error never echoes the header.
func TestIDTokenHeaderStrict(t *testing.T) {
	t.Parallel()

	headers := map[string]string{
		"typ twice":              `{"alg":"RS256","kid":"rsa-1","typ":"JWT","typ":"at+jwt"}`,
		"typ at+jwt then JWT":    `{"alg":"RS256","kid":"rsa-1","typ":"at+jwt","typ":"JWT"}`,
		"escaped duplicate typ":  `{"alg":"RS256","kid":"rsa-1","typ":"JWT","t\u0079p":"at+jwt"}`,
		"escaped duplicate alg":  `{"alg":"RS256","\u0061lg":"none","kid":"rsa-1-at+jwt"}`,
		"escaped duplicate jwk":  `{"alg":"RS256","kid":"rsa-1-at+jwt","jwk":null,"\u006a\u0077\u006b":null}`,
		"case variant Typ":       `{"alg":"RS256","kid":"rsa-1","Typ":"at+jwt","typ":"JWT"}`,
		"alg twice":              `{"alg":"none","alg":"RS256","kid":"rsa-1"}`,
		"kid twice":              `{"alg":"RS256","kid":"other-at+jwt","kid":"rsa-1"}`,
		"unpaired surrogate":     `{"alg":"RS256","kid":"rsa-1","x":"\udc00 at+jwt"}`,
		"invalid UTF-8":          "{\"alg\":\"RS256\",\"kid\":\"rsa-1\",\"x\":\"\xff at+jwt\"}",
		"array":                  `["at+jwt"]`,
		"not JSON":               `at+jwt`,
		"trailing data":          `{"alg":"RS256","kid":"rsa-1"} at+jwt`,
		"number out of range":    `{"alg":"RS256","kid":"rsa-1","x":1e999}`,
		"deeper than 32 levels":  `{"alg":"RS256","kid":"rsa-1","x":` + strings.Repeat("[", 40) + strings.Repeat("]", 40) + `}`,
		"over 4096 bytes (4097)": paddedHeader(4097),
	}

	for name, h := range headers {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if strings.HasPrefix(name, "escaped") {
				require.Contains(t, h, `\u00`, "the member name is written with a JSON escape")
			}

			id, err := headerLogin(t, h)
			require.ErrorIs(t, err, oidcclient.ErrIDTokenMalformed)
			assert.Nil(t, id)
			assert.NotContains(t, err.Error(), "at+jwt", "the header is never echoed")
			assert.NotContains(t, err.Error(), "999", "the header is never echoed")
		})
	}

	for name, tok := range map[string]string{
		"header not base64url": "e30*.e30.c2ln",
		"padded header":        "e30=.e30.c2ln",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t)
			op.set(func(op *fakeOP) { op.idTokenHook = func(*grant) string { return tok } })

			_, err := op.login(t, op.client(t))
			require.ErrorIs(t, err, oidcclient.ErrIDTokenMalformed)
			assert.Contains(t, err.Error(), "JOSE header is not base64url")
		})
	}

	t.Run("exactly 4096 bytes", func(t *testing.T) {
		t.Parallel()

		id, err := headerLogin(t, paddedHeader(4096))
		require.NoError(t, err)
		assert.Equal(t, testSubject, id.Subject)
	})
}

// paddedHeader returns a valid RS256 header of exactly size bytes.
func paddedHeader(size int) string {
	const prefix, suffix = `{"alg":"RS256","kid":"rsa-1","typ":"JWT","pad":"`, `"}`

	return prefix + strings.Repeat("p", size-len(prefix)-len(suffix)) + suffix
}
