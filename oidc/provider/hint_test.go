// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/hyperscale-stack/security/oauth2"
	oidcprovider "github.com/hyperscale-stack/security/oidc/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hintClaims are the claims of an ID Token the provider issued to the web
// client for alice — expired an hour ago.
func hintClaims() map[string]any {
	now := newTestClock().Now()

	return map[string]any{
		"iss": testIssuer, "sub": "alice", "aud": webClientID,
		"iat": now.Add(-2 * time.Hour).Unix(), "exp": now.Add(-time.Hour).Unix(),
	}
}

// signHint signs claims with key, typ JWT.
func signHint(t *testing.T, key jwtsec.PrivateKey, claims map[string]any) string {
	t.Helper()

	signer, err := jwtsec.NewSigner(key)
	require.NoError(t, err)

	jws, err := signer.Sign(context.Background(), claims)
	require.NoError(t, err)

	return jws
}

// signHintTyped signs claims with key and the given typ header.
func signHintTyped(t *testing.T, key jwtsec.PrivateKey, typ string, claims map[string]any) string {
	t.Helper()

	signer, err := jwtsec.NewSigner(key, jwtsec.WithType(typ))
	require.NoError(t, err)

	jws, err := signer.Sign(context.Background(), claims)
	require.NoError(t, err)

	return jws
}

// TestIDTokenHint pins OIDC Core §3.1.2.1 and §3.1.2.2: the provider
// validates that it issued the hint — any of its published keys, its
// issuer, the requesting client among the audiences — accepts it expired,
// and answers only for the end-user it designates.
func TestIDTokenHint(t *testing.T) {
	t.Parallel()

	withAud := func(aud any) map[string]any {
		c := hintClaims()
		c["aud"] = aud

		return c
	}

	without := func(claim string) map[string]any {
		c := hintClaims()
		delete(c, claim)

		return c
	}

	cases := []struct {
		name string
		hint func(t *testing.T) string
		ok   bool
	}{
		{"expired hint", func(t *testing.T) string { return signHint(t, signingRSA(), hintClaims()) }, true},
		{"hint signed with ES256", func(t *testing.T) string { return signHint(t, signingEC(), hintClaims()) }, true},
		{"audience array with the client", func(t *testing.T) string {
			return signHint(t, signingRSA(), withAud([]string{"other", webClientID}))
		}, true},
		{"typ application/jwt", func(t *testing.T) string { return signHintTyped(t, signingRSA(), "application/jwt", hintClaims()) }, true},
		{"unknown key", func(t *testing.T) string {
			return signHint(t, jwtsec.PrivateKey{KeyID: "rogue", Algorithm: jwtsec.RS256, Key: rsaKeyB}, hintClaims())
		}, false},
		{"known kid, other key", func(t *testing.T) string {
			return signHint(t, jwtsec.PrivateKey{KeyID: "rsa-a", Algorithm: jwtsec.RS256, Key: rsaKeyB}, hintClaims())
		}, false},
		{"other issuer", func(t *testing.T) string {
			c := hintClaims()
			c["iss"] = "https://evil.example"

			return signHint(t, signingRSA(), c)
		}, false},
		{"another client's hint", func(t *testing.T) string { return signHint(t, signingRSA(), withAud("other")) }, false},
		{"no audience", func(t *testing.T) string { return signHint(t, signingRSA(), without("aud")) }, false},
		{"no sub", func(t *testing.T) string { return signHint(t, signingRSA(), without("sub")) }, false},
		{"sub over 255 bytes", func(t *testing.T) string {
			c := hintClaims()
			c["sub"] = strings.Repeat("s", 256)

			return signHint(t, signingRSA(), c)
		}, false},
		{"an access token", func(t *testing.T) string { return signHintTyped(t, signingRSA(), jwtsec.TypeAccessToken, hintClaims()) }, false},
		{"HS256 with the public key", func(t *testing.T) string { return hmacHint(t) }, false},
		{"alg none", func(*testing.T) string {
			payload, _ := json.Marshal(hintClaims())

			return b64(`{"alg":"none"}`) + "." + base64.RawURLEncoding.EncodeToString(payload) + "."
		}, false},
		{"encrypted (five parts)", func(*testing.T) string { return "a.b.c.d.e" }, false},
		{"payload not an object", func(t *testing.T) string {
			signer, err := jwtsec.NewSigner(signingRSA())
			require.NoError(t, err)

			jws, err := signer.Sign(context.Background(), []string{"x"})
			require.NoError(t, err)

			return jws
		}, false},
		{"garbage", func(*testing.T) string { return "not-a-jwt" }, false},
		{"oversized", func(t *testing.T) string {
			c := hintClaims()
			c["pad"] = strings.Repeat("p", 17*1024)

			return signHint(t, signingRSA(), c)
		}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newEnv(t)
			params := redirect(t, e.authorize(with(authorizeQuery(), "id_token_hint", tc.hint(t))))

			if !tc.ok {
				assert.Equal(t, oauth2.CodeInvalidRequest, params.Get("error"))

				interactive, silent := e.interaction.calls()
				assert.Empty(t, interactive)
				assert.Empty(t, silent)

				return
			}

			assert.NotEmpty(t, params.Get("code"))
			assert.Equal(t, []string{"alice"}, e.lastRequest().Subjects)
		})
	}
}

// TestIDTokenHintOfARetiredKey: a key kept in the published list still
// identifies the provider's own hints (rotation, Core §10.1.1).
func TestIDTokenHintOfARetiredKey(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	e.keys.set(oidcprovider.KeyRing{
		Signing:   []jwtsec.PrivateKey{signingRSAB()},
		Published: []jwtsec.PublicKey{publicOf(signingRSA())},
	})

	params := redirect(t, e.authorize(with(authorizeQuery(), "id_token_hint", signHint(t, signingRSA(), hintClaims()))))
	assert.NotEmpty(t, params.Get("code"))

	e.keys.set(oidcprovider.KeyRing{Signing: []jwtsec.PrivateKey{signingRSAB()}})
	params = redirect(t, e.authorize(with(authorizeQuery(), "id_token_hint", signHint(t, signingRSA(), hintClaims()))))
	assert.Equal(t, oauth2.CodeInvalidRequest, params.Get("error"), "a removed key identifies nothing")
}

// TestIDTokenHintDesignatesTheEndUser pins Core §3.1.2.1 (errata 2): when
// the end-user is not the hinted one, the provider MUST answer an error —
// login_required — never an ID Token for another user.
func TestIDTokenHintDesignatesTheEndUser(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	c := hintClaims()
	c["sub"] = "bob"

	for _, prompt := range []string{"", "none"} {
		q := with(authorizeQuery(), "id_token_hint", signHint(t, signingRSA(), c), "prompt", prompt)
		params := redirect(t, e.authorize(q))
		assert.Equal(t, oauth2.CodeLoginRequired, params.Get("error"), "prompt=%q", prompt)
	}

	q := with(authorizeQuery(), "id_token_hint", signHint(t, signingRSA(), c), "claims", `{"id_token": {"sub": {"value": "carol"}}}`)
	assert.Equal(t, oauth2.CodeInvalidRequest, redirect(t, e.authorize(q)).Get("error"), "hint and claims designate different users")
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// hmacHint forges an HS256 hint keyed with the DER encoding of the RSA
// public key — algorithm confusion.
func hmacHint(t *testing.T) string {
	t.Helper()

	der, err := x509.MarshalPKIXPublicKey(&rsaKeyA.PublicKey)
	require.NoError(t, err)

	payload, err := json.Marshal(hintClaims())
	require.NoError(t, err)

	signing := b64(`{"alg":"HS256","kid":"rsa-a","typ":"JWT"}`) + "." + base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, der)
	mac.Write([]byte(signing))

	return signing + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
