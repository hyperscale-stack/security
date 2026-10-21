// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	"github.com/stretchr/testify/require"
)

// pssSigned makes the OP sign its ID Tokens with RSASSA-PSS (alg, hash)
// and a salt of saltLength bytes (rsa.PSSSaltLengthAuto: the maximum — Go
// cannot sign with an empty salt), its key published for alg.
func pssSigned(alg jose.SignatureAlgorithm, hash crypto.Hash, saltLength int) func(op *fakeOP) {
	return func(op *fakeOP) {
		signWith(keyRSA(alg, "k"))(op)

		op.idTokenHook = func(g *grant) string {
			header, err := json.Marshal(map[string]string{"alg": string(alg), "kid": "k", "typ": "JWT"})
			require.NoError(op.t, err)

			payload, err := json.Marshal(op.idClaims(g))
			require.NoError(op.t, err)

			input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)

			h := hash.New()
			h.Write([]byte(input))

			priv, ok := op.signer.priv.(*rsa.PrivateKey)
			require.True(op.t, ok)

			sig, err := rsa.SignPSS(rand.Reader, priv, hash, h.Sum(nil), &rsa.PSSOptions{SaltLength: saltLength, Hash: hash})
			require.NoError(op.t, err)

			return input + "." + base64.RawURLEncoding.EncodeToString(sig)
		}
	}
}

// TestIDTokenPSSSaltLength checks that a PS256/384/512 signature verifies
// only with a salt as long as the hash output — RFC 7518 §3.5: "The size of
// the salt value is the same size as the hash function output" — not with
// the other lengths RSASSA-PSS (RFC 8017 §9.1) admits.
func TestIDTokenPSSSaltLength(t *testing.T) {
	t.Parallel()

	var cases []idCase

	for _, ps := range []struct {
		alg  jose.SignatureAlgorithm
		hash crypto.Hash
	}{{jose.PS256, crypto.SHA256}, {jose.PS384, crypto.SHA384}, {jose.PS512, crypto.SHA512}} {
		size := ps.hash.Size()

		for _, salt := range []int{1, size - 1, size, size + 1, rsa.PSSSaltLengthAuto} {
			name := string(ps.alg) + " salt " + strconv.Itoa(salt)
			if salt == rsa.PSSSaltLengthAuto {
				name = string(ps.alg) + " maximum salt"
			}

			tc := idCase{name: name, setup: pssSigned(ps.alg, ps.hash, salt), config: onlyAlgorithm(ps.alg)}
			if salt != size {
				tc.err = oidcclient.ErrIDTokenSignature
			}

			cases = append(cases, tc)
		}
	}

	runIDCases(t, cases)
}

// mustHex decodes a hex constant.
func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}

	return b
}

// TestIDTokenEd25519KeyValidation checks that a JWK Set key whose Ed25519
// encoding is not canonical — y not below p, RFC 8032 §5.1.3 step 1, which
// makes its decoding fail (§5.1.7 step 1) — or that is a point of small
// order (RFC 8725 §3.4: validate cryptographic inputs) is ignored, as an
// unusable key (RFC 7517 §5): an ID Token naming it fails with
// ErrUnknownSigningKey, never reaching a signature check. A small-order key
// verifies forged signatures: S = 0 and R = the identity point verify any
// message under the identity key.
func TestIDTokenEd25519KeyValidation(t *testing.T) {
	t.Parallel()

	identityForgery := func(op *fakeOP, g *grant) string {
		header, err := json.Marshal(map[string]string{"alg": "EdDSA", "kid": "ed", "typ": "JWT"})
		require.NoError(op.t, err)

		payload, err := json.Marshal(op.idClaims(g))
		require.NoError(op.t, err)

		sig := append(mustHex("0100000000000000000000000000000000000000000000000000000000000000"), make([]byte, 32)...)

		return base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload) +
			"." + base64.RawURLEncoding.EncodeToString(sig)
	}

	// publish serves a JWK Set of the one Ed25519 key, written by hand:
	// go-jose refuses to encode some of these keys.
	publish := func(key []byte) func(op *fakeOP) {
		return func(op *fakeOP) {
			signWith(keyEd("ed"))(op)

			raw, err := json.Marshal(map[string]any{"keys": []map[string]string{{
				"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(key),
				"kid": "ed", "alg": "EdDSA", "use": "sig",
			}}})
			require.NoError(op.t, err)

			op.jwksRaw = raw
			op.idTokenHook = func(g *grant) string { return identityForgery(op, g) }
		}
	}

	runIDCases(t, []idCase{
		{
			name: "identity key: a forged signature", err: oidcclient.ErrUnknownSigningKey, config: onlyAlgorithm(jose.EdDSA),
			setup: publish(mustHex("0100000000000000000000000000000000000000000000000000000000000000")),
		},
		{
			name: "non-canonical encoding p+3", err: oidcclient.ErrUnknownSigningKey, config: onlyAlgorithm(jose.EdDSA),
			setup: publish(mustHex("f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")),
		},
		{
			name: "non-canonical encoding p+3, sign bit set", err: oidcclient.ErrUnknownSigningKey, config: onlyAlgorithm(jose.EdDSA),
			setup: publish(mustHex("f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
		},
		{
			name: "a valid key verifies its own signatures", config: onlyAlgorithm(jose.EdDSA),
			setup: signWith(keyEd("ed")),
		},
	})
}
