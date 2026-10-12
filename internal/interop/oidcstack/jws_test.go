// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcstack_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/stretchr/testify/require"
)

// A small JWS Compact Serialization toolkit (RFC 7515) on the standard
// library only: the tests forge tokens with headers and keys no signer of
// this repository would produce, without relying on the JOSE library the
// client itself uses.

var b64 = base64.RawURLEncoding

// jwsParts returns the decoded header and payload of a compact JWS.
func jwsParts(t *testing.T, jws string) (header, payload map[string]any) {
	t.Helper()

	parts := strings.Split(jws, ".")
	require.Len(t, parts, 3, "a compact JWS")

	for i, into := range []*map[string]any{&header, &payload} {
		raw, err := b64.DecodeString(parts[i])
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(raw, into))
	}

	return header, payload
}

// signJWS signs header and payload with key under alg: RS256 (RSASSA-PKCS1
// v1.5), PS256 (RSASSA-PSS), ES256 (P-256, r ‖ s), HS256 (an HMAC keyed by
// secret) or none (no signature).
func signJWS(t *testing.T, alg string, key any, header, payload map[string]any) string {
	t.Helper()

	header["alg"] = alg

	h, err := json.Marshal(header)
	require.NoError(t, err)

	p, err := json.Marshal(payload)
	require.NoError(t, err)

	input := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	digest := sha256.Sum256([]byte(input))

	var sig []byte

	switch alg {
	case "RS256":
		sig, err = rsa.SignPKCS1v15(rand.Reader, key.(*rsa.PrivateKey), crypto.SHA256, digest[:])
	case "PS256":
		sig, err = rsa.SignPSS(rand.Reader, key.(*rsa.PrivateKey), crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	case "ES256":
		var r, s *big.Int

		r, s, err = ecdsa.Sign(rand.Reader, key.(*ecdsa.PrivateKey), digest[:])
		sig = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	case "HS256":
		mac := hmac.New(sha256.New, key.([]byte))
		mac.Write([]byte(input))
		sig = mac.Sum(nil)
	case "none":
	default:
		t.Fatalf("unsupported alg %s", alg)
	}

	require.NoError(t, err)

	return input + "." + b64.EncodeToString(sig)
}

// resign returns jws with its header and claims edited, signed again with
// key under alg.
func resign(t *testing.T, jws, alg string, key any, editHeader, editClaims func(map[string]any)) string {
	t.Helper()

	header, payload := jwsParts(t, jws)
	if editHeader != nil {
		editHeader(header)
	}

	if editClaims != nil {
		editClaims(payload)
	}

	return signJWS(t, alg, key, header, payload)
}

// publicJWK is the public JWK of an RSA key (RFC 7518 §6.3.1).
func publicJWK(k *rsa.PrivateKey, kid string) map[string]any {
	return map[string]any{
		"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
		"n": b64.EncodeToString(k.N.Bytes()), "e": b64.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
	}
}

// publicKeys returns the public halves of ring's keys, for verification.
func publicKeys(t *testing.T, keys ...jwtsec.PrivateKey) []jwtsec.PublicKey {
	t.Helper()

	out := make([]jwtsec.PublicKey, 0, len(keys))

	for _, k := range keys {
		pub, err := k.Public()
		require.NoError(t, err)

		out = append(out, pub)
	}

	return out
}
