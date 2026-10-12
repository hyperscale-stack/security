// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	jwtsec "github.com/hyperscale-stack/security/jwt"
	oidcprovider "github.com/hyperscale-stack/security/oidc/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyRingValidate(t *testing.T) {
	t.Parallel()

	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	ps256A := jwtsec.PrivateKey{KeyID: "rsa-a-ps", Algorithm: jwtsec.PS256, Key: rsaKeyA}
	es384 := jwtsec.PrivateKey{KeyID: "ec-384", Algorithm: jwtsec.ES384, Key: ec384}

	cases := []struct {
		name string
		ring oidcprovider.KeyRing
		ok   bool
	}{
		{"RS256 only", oidcprovider.KeyRing{Signing: []jwtsec.PrivateKey{signingRSA()}}, true},
		{"several algorithms", oidcprovider.KeyRing{Signing: []jwtsec.PrivateKey{signingEC(), signingRSA(), es384}}, true},
		{"next and retired keys published", oidcprovider.KeyRing{
			Signing:   []jwtsec.PrivateKey{signingRSA()},
			Published: []jwtsec.PublicKey{publicOf(signingRSAB()), publicOf(signingEC())},
		}, true},
		{"an EdDSA verification key published (e.g. for access tokens)", oidcprovider.KeyRing{
			Signing:   []jwtsec.PrivateKey{signingRSA()},
			Published: []jwtsec.PublicKey{{KeyID: "ed", Algorithm: jwtsec.EdDSA, Key: edPub}},
		}, true},
		{"no signing key", oidcprovider.KeyRing{}, false},
		{"no RS256 signing key", oidcprovider.KeyRing{Signing: []jwtsec.PrivateKey{signingEC()}}, false},
		{"two RS256 signing keys", oidcprovider.KeyRing{Signing: []jwtsec.PrivateKey{signingRSA(), signingRSAB()}}, false},
		{"EdDSA signing key", oidcprovider.KeyRing{Signing: []jwtsec.PrivateKey{
			signingRSA(), {KeyID: "ed", Algorithm: jwtsec.EdDSA, Key: edPriv},
		}}, false},
		{"HMAC signing key", oidcprovider.KeyRing{Signing: []jwtsec.PrivateKey{
			signingRSA(), {KeyID: "hs", Algorithm: jwtsec.HS256, Key: []byte("0123456789abcdef0123456789abcdef")},
		}}, false},
		{"signing key without kid", oidcprovider.KeyRing{Signing: []jwtsec.PrivateKey{
			{Algorithm: jwtsec.RS256, Key: rsaKeyA},
		}}, false},
		{"signing key without algorithm", oidcprovider.KeyRing{Signing: []jwtsec.PrivateKey{
			signingRSA(), {KeyID: "x", Key: ecKey},
		}}, false},
		{"RSA signing key below 2048 bits", oidcprovider.KeyRing{Signing: []jwtsec.PrivateKey{
			{KeyID: "small", Algorithm: jwtsec.RS256, Key: rsa1024},
		}}, false},
		{"duplicated kid across lists", oidcprovider.KeyRing{
			Signing:   []jwtsec.PrivateKey{signingRSA()},
			Published: []jwtsec.PublicKey{{KeyID: "rsa-a", Algorithm: jwtsec.RS256, Key: &rsaKeyB.PublicKey}},
		}, false},
		{"duplicated kid among published keys", oidcprovider.KeyRing{
			Signing:   []jwtsec.PrivateKey{signingRSA()},
			Published: []jwtsec.PublicKey{publicOf(signingRSAB()), publicOf(signingRSAB())},
		}, false},
		{"one RSA key under two algorithms", oidcprovider.KeyRing{Signing: []jwtsec.PrivateKey{signingRSA(), ps256A}}, false},
		{"signing key published again under another kid", oidcprovider.KeyRing{
			Signing:   []jwtsec.PrivateKey{signingRSA()},
			Published: []jwtsec.PublicKey{{KeyID: "again", Algorithm: jwtsec.RS256, Key: &rsaKeyA.PublicKey}},
		}, false},
		{"private key in the published list", oidcprovider.KeyRing{
			Signing:   []jwtsec.PrivateKey{signingRSA()},
			Published: []jwtsec.PublicKey{{KeyID: "leak", Algorithm: jwtsec.RS256, Key: rsaKeyB}},
		}, false},
		{"symmetric key in the published list", oidcprovider.KeyRing{
			Signing:   []jwtsec.PrivateKey{signingRSA()},
			Published: []jwtsec.PublicKey{{KeyID: "hs", Algorithm: jwtsec.HS256, Key: []byte("0123456789abcdef0123456789abcdef")}},
		}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.ring.Validate()
			if tc.ok {
				require.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, oidcprovider.ErrInvalidKeyRing)
		})
	}
}

func TestStaticKeys(t *testing.T) {
	t.Parallel()

	_, err := oidcprovider.StaticKeys(oidcprovider.KeyRing{Signing: []jwtsec.PrivateKey{signingEC()}})
	require.ErrorIs(t, err, oidcprovider.ErrInvalidKeyRing)

	src, err := oidcprovider.StaticKeys(oidcprovider.KeyRing{
		Signing:   []jwtsec.PrivateKey{signingRSA()},
		Published: []jwtsec.PublicKey{publicOf(signingRSAB())},
	})
	require.NoError(t, err)

	ring, err := src.Keys(context.Background(), "https://any.example")
	require.NoError(t, err)
	require.Len(t, ring.Signing, 1)
	require.Len(t, ring.Published, 1)

	// The source hands out copies: a caller mutating its ring changes nothing.
	ring.Signing[0] = signingEC()
	ring.Published[0] = publicOf(signingEC())

	again, err := src.Keys(context.Background(), "https://any.example")
	require.NoError(t, err)
	assert.Equal(t, "rsa-a", again.Signing[0].KeyID)
	assert.Equal(t, "rsa-b", again.Published[0].KeyID)
}

// jwksKeys fetches the JWK Set and returns its keys.
func jwksKeys(t *testing.T, e *env, r *http.Request) []map[string]any {
	t.Helper()

	rec := serve(e.op.JWKSHandler(), r)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &doc))

	return doc.Keys
}

func kids(keys []map[string]any) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		kid, _ := k["kid"].(string)
		out = append(out, kid)
	}

	return out
}

// TestJWKSPublishesPublicKeysOnly pins RFC 7517 §5 and OIDC Discovery §3:
// the signing keys' public halves and the published keys, each with kid,
// alg and use "sig", and never private or symmetric material.
func TestJWKSPublishesPublicKeysOnly(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	e.keys.set(oidcprovider.KeyRing{
		Signing:   []jwtsec.PrivateKey{signingRSA(), signingEC()},
		Published: []jwtsec.PublicKey{publicOf(signingRSAB())},
	})

	rec := serve(e.op.JWKSHandler(), get("/.well-known/jwks.json"))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Equal(t, "max-age=300", rec.Header().Get("Cache-Control"))

	keys := jwksKeys(t, e, get("/.well-known/jwks.json"))
	assert.Equal(t, []string{"rsa-a", "ec-1", "rsa-b"}, kids(keys))

	for _, k := range keys {
		assert.Equal(t, "sig", k["use"])
		assert.NotEmpty(t, k["alg"])

		for _, member := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
			assert.NotContains(t, k, member)
		}
	}

	assert.NotContains(t, rec.Body.String(), `"d"`)
}

func TestJWKSMethodsAndHead(t *testing.T) {
	t.Parallel()

	e := newEnv(t)

	head := serve(e.op.JWKSHandler(), httptest.NewRequest(http.MethodHead, "/.well-known/jwks.json", nil))
	assert.Equal(t, http.StatusOK, head.Code)

	post := serve(e.op.JWKSHandler(), httptest.NewRequest(http.MethodPost, "/.well-known/jwks.json", nil))
	assert.Equal(t, http.StatusMethodNotAllowed, post.Code)
	assert.Equal(t, "GET, HEAD", post.Header().Get("Allow"))
}

func TestJWKSIsPerIssuer(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	e.keys.setFor("https://b.example", oidcprovider.KeyRing{Signing: []jwtsec.PrivateKey{signingRSAB()}})

	a := get("/.well-known/jwks.json")
	a.Host = "a.example"

	b := get("/.well-known/jwks.json")
	b.Host = "b.example"

	assert.Equal(t, []string{"rsa-a", "ec-1"}, kids(jwksKeys(t, e, a)))
	assert.Equal(t, []string{"rsa-b"}, kids(jwksKeys(t, e, b)))
}

func TestJWKSFailsClosed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		setup func(*env)
		opts  []envOption
		cause error
	}{
		{"key source error", func(e *env) { e.keys.fail(errors.New("kms down")) }, nil, nil},
		{"invalid ring", func(e *env) {
			e.keys.set(oidcprovider.KeyRing{
				Signing:   []jwtsec.PrivateKey{signingRSA()},
				Published: []jwtsec.PublicKey{{KeyID: "leak", Algorithm: jwtsec.RS256, Key: rsaKeyB}},
			})
		}, nil, oidcprovider.ErrInvalidKeyRing},
		{"invalid issuer", nil, []envOption{withResolver(fixedIssuer{issuer: "http://op.example"})}, oidcprovider.ErrInvalidIssuer},
		{"issuer resolver error", nil, []envOption{withResolver(fixedIssuer{err: errors.New("no tenant")})}, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newEnv(t, tc.opts...)
			if tc.setup != nil {
				tc.setup(e)
			}

			rec := serve(e.op.JWKSHandler(), get("/.well-known/jwks.json"))
			assert.Equal(t, http.StatusInternalServerError, rec.Code)
			assert.NotContains(t, rec.Body.String(), "keys", "nothing is published")
			require.NotEmpty(t, e.sink.all(), "the cause reaches the error hook")

			if tc.cause != nil {
				assert.True(t, e.sink.contains(tc.cause))
			}
		})
	}
}

// TestKeyRotationThroughJWKS follows OIDC Core §10.1.1: the next key is
// published before it signs, the retired key stays published after.
func TestKeyRotationThroughJWKS(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	k1, k2 := signingRSA(), signingRSAB()

	stages := []struct {
		ring oidcprovider.KeyRing
		want []string
	}{
		{oidcprovider.KeyRing{Signing: []jwtsec.PrivateKey{k1}}, []string{"rsa-a"}},
		{oidcprovider.KeyRing{Signing: []jwtsec.PrivateKey{k1}, Published: []jwtsec.PublicKey{publicOf(k2)}}, []string{"rsa-a", "rsa-b"}},
		{oidcprovider.KeyRing{Signing: []jwtsec.PrivateKey{k2}, Published: []jwtsec.PublicKey{publicOf(k1)}}, []string{"rsa-b", "rsa-a"}},
		{oidcprovider.KeyRing{Signing: []jwtsec.PrivateKey{k2}}, []string{"rsa-b"}},
	}

	for _, s := range stages {
		e.keys.set(s.ring)
		assert.Equal(t, s.want, kids(jwksKeys(t, e, get("/.well-known/jwks.json"))))
	}
}
