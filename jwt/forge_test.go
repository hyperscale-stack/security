// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"strings"
	"testing"
	"time"

	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/stretchr/testify/require"
)

// b64 is the unpadded base64url encoding of the JWS compact serialization.
var b64 = base64.RawURLEncoding

// forge signs a header and a payload given as raw bytes — JSON a go-jose
// signer would never produce (duplicate or case-variant names, crit, b64,
// invalid UTF-8…) — with key under alg, and returns the compact JWS.
func forge(t *testing.T, alg jwtsec.Algorithm, key any, header, payload string) string {
	t.Helper()

	input := b64.EncodeToString([]byte(header)) + "." + b64.EncodeToString([]byte(payload))

	return input + "." + b64.EncodeToString(signInput(t, alg, key, []byte(input)))
}

// signInput computes the JWS signature of input (RFC 7515 §5.1, RFC 7518 §3).
func signInput(t *testing.T, alg jwtsec.Algorithm, key any, input []byte) []byte {
	t.Helper()

	switch alg {
	case jwtsec.EdDSA:
		k, ok := key.(ed25519.PrivateKey)
		require.True(t, ok, "EdDSA needs an ed25519.PrivateKey")

		return ed25519.Sign(k, input)
	case jwtsec.ES256, jwtsec.ES384, jwtsec.ES512:
		return signECDSA(t, alg, key, input)
	case jwtsec.RS256, jwtsec.RS384, jwtsec.RS512, jwtsec.PS256, jwtsec.PS384, jwtsec.PS512:
		return signRSA(t, alg, key, input)
	case jwtsec.HS256, jwtsec.HS384, jwtsec.HS512:
		k, ok := key.([]byte)
		require.True(t, ok, "HS* needs a []byte secret")

		m := hmac.New(map[jwtsec.Algorithm]func() hash.Hash{
			jwtsec.HS256: sha256.New, jwtsec.HS384: sha512.New384, jwtsec.HS512: sha512.New,
		}[alg], k)
		m.Write(input)

		return m.Sum(nil)
	}

	t.Fatalf("forge: unsupported algorithm %s", alg)

	return nil
}

func digest(h crypto.Hash, input []byte) []byte {
	d := h.New()
	d.Write(input)

	return d.Sum(nil)
}

func signECDSA(t *testing.T, alg jwtsec.Algorithm, key any, input []byte) []byte {
	t.Helper()

	k, ok := key.(*ecdsa.PrivateKey)
	require.True(t, ok, "ES* needs an *ecdsa.PrivateKey")

	h := map[jwtsec.Algorithm]crypto.Hash{jwtsec.ES256: crypto.SHA256, jwtsec.ES384: crypto.SHA384, jwtsec.ES512: crypto.SHA512}[alg]
	size := (k.Curve.Params().BitSize + 7) / 8

	r, s, err := ecdsa.Sign(rand.Reader, k, digest(h, input))
	require.NoError(t, err)

	out := make([]byte, 2*size)
	r.FillBytes(out[:size])
	s.FillBytes(out[size:])

	return out
}

func signRSA(t *testing.T, alg jwtsec.Algorithm, key any, input []byte) []byte {
	t.Helper()

	k, ok := key.(*rsa.PrivateKey)
	require.True(t, ok, "RS*/PS* need an *rsa.PrivateKey")

	h := map[jwtsec.Algorithm]crypto.Hash{
		jwtsec.RS256: crypto.SHA256, jwtsec.RS384: crypto.SHA384, jwtsec.RS512: crypto.SHA512,
		jwtsec.PS256: crypto.SHA256, jwtsec.PS384: crypto.SHA384, jwtsec.PS512: crypto.SHA512,
	}[alg]

	var (
		sig []byte
		err error
	)

	if strings.HasPrefix(string(alg), "PS") {
		sig, err = rsa.SignPSS(rand.Reader, k, h, digest(h, input), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	} else {
		sig, err = rsa.SignPKCS1v15(rand.Reader, k, h, digest(h, input))
	}

	require.NoError(t, err)

	return sig
}

// esc returns the JSON escape of the UTF-16 code unit hex (RFC 8259 §7),
// e.g. esc("0075") for u. Built at run time so that the test sources hold
// no escape sequence a tool could normalise into the character itself.
func esc(hex string) string { return `\` + "u" + hex }

// header returns a JOSE header naming alg and kid.
func header(alg jwtsec.Algorithm, kid string) string {
	return fmt.Sprintf(`{"alg":%q,"kid":%q}`, alg, kid)
}

// in returns the NumericDate d from now.
func in(d time.Duration) int64 { return time.Now().Add(d).Unix() }
