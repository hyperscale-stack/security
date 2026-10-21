// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"

	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/hyperscale-stack/security/oauth2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rawHint signs the raw JOSE header and the hint claims with the
// provider's RS256 key: a hint the provider did issue, but for its header.
func rawHint(t *testing.T, header string) string {
	t.Helper()

	payload, err := json.Marshal(hintClaims())
	require.NoError(t, err)

	input := b64(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(input))

	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKeyA, crypto.SHA256, sum[:])
	require.NoError(t, err)

	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// advisoryJWK is the "jwk" member of GHSA-mgcc-cww5-fp2q: an RSA private
// JWK whose p has primeBits bits, which go-jose v4.1.5 validated — at a
// cost cubic in its size — before any check.
func advisoryJWK(primeBits int) string {
	enc := func(x *big.Int) string { return base64.RawURLEncoding.EncodeToString(x.Bytes()) }

	one := big.NewInt(1)
	n := new(big.Int).Add(new(big.Int).Lsh(one, 2048), one)
	p := new(big.Int).Add(new(big.Int).Lsh(one, uint(primeBits-1)), one)

	return fmt.Sprintf(`{"kty":"RSA","n":%q,"e":"AQAB","d":"Aw","p":%q,"q":"Aw"}`, enc(n), enc(p))
}

// TestIDTokenHintKeyBearingHeaders pins that the id_token_hint goes
// through jwtsec's header check (audit F-01): a hint whose header carries
// or locates a key — jwk, x5c, jku, x5u — is refused before go-jose parses
// it, whatever the member's value, even when the provider's own key signed
// it (OpenID Connect Core §2: ID Tokens SHOULD NOT use them; §3.1.2.2: the
// provider validates the hint with its own keys). The unauthenticated GET
// /authorize no longer reaches the advisory's CPU-bound key validation.
func TestIDTokenHintKeyBearingHeaders(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, member, header string
	}{
		{"jwk of the advisory", "jwk", `{"alg":"RS256","kid":"rsa-a","typ":"JWT","jwk":` + advisoryJWK(4096) + `}`},
		{"jwk null", "jwk", `{"alg":"RS256","kid":"rsa-a","jwk":null}`},
		{"x5c", "x5c", `{"alg":"RS256","kid":"rsa-a","x5c":["MIIB"]}`},
		{"jku", "jku", `{"alg":"RS256","kid":"rsa-a","jku":"https://attacker.example/jwks"}`},
		{"x5u", "x5u", `{"alg":"RS256","kid":"rsa-a","x5u":"https://attacker.example/cert.pem"}`},
	}

	t.Run("control", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t)
		params := redirect(t, e.authorize(with(authorizeQuery(), "id_token_hint", rawHint(t, `{"alg":"RS256","kid":"rsa-a","typ":"JWT"}`))))
		assert.NotEmpty(t, params.Get("code"), "the forged hint is otherwise valid")
	})

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newEnv(t)
			params := redirect(t, e.authorize(with(authorizeQuery(), "id_token_hint", rawHint(t, tc.header))))
			assert.Equal(t, oauth2.CodeInvalidRequest, params.Get("error"))

			interactive, silent := e.interaction.calls()
			assert.Empty(t, interactive)
			assert.Empty(t, silent)

			want := fmt.Sprintf("unsupported %q header parameter", tc.member)
			assert.True(t, hookedCause(e, jwtsec.ErrMalformedToken, want), "jwtsec refused the %s header before go-jose parsed it", tc.member)
		})
	}
}

// hookedCause reports whether the ErrorHook got an *oauth2.Error matching
// target whose cause reads want.
func hookedCause(e *env, target error, want string) bool {
	for _, err := range e.sink.all() {
		var oe *oauth2.Error
		if errors.Is(err, target) && errors.As(err, &oe) && oe.Cause != nil && strings.Contains(oe.Cause.Error(), want) {
			return true
		}
	}

	return false
}
