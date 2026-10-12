// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcop_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xoauth2 "golang.org/x/oauth2"
)

// claimsOfToken decodes every claim of an ID Token go-oidc verified.
func claimsOfToken(t *testing.T, idToken *oidc.IDToken) map[string]any {
	t.Helper()

	var claims map[string]any
	require.NoError(t, idToken.Claims(&claims))

	return claims
}

// userInfoClaims calls UserInfo through go-oidc with the access token of
// tok and decodes every claim of the answer.
func (r *rp) userInfoClaims(t *testing.T, tok *xoauth2.Token) map[string]any {
	t.Helper()

	info, err := r.provider.UserInfo(r.ctx, xoauth2.StaticTokenSource(tok))
	require.NoError(t, err)

	var claims map[string]any
	require.NoError(t, info.Claims(&claims))

	return claims
}

// jwsHeader decodes the protected header of a compact JWS.
func jwsHeader(t *testing.T, raw string) map[string]any {
	t.Helper()

	encoded, _, ok := strings.Cut(raw, ".")
	require.True(t, ok, "a compact JWS")

	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	require.NoError(t, err)

	var header map[string]any
	require.NoError(t, json.Unmarshal(decoded, &header))

	return header
}

// TestInteropClaimsParameter pins OpenID Connect Core §5.5 with go-oidc:
// claims requested individually, under the openid scope alone, are
// returned where they were requested — email in the ID Token, name from
// UserInfo — and only those the end-user agreed to release: phone_number,
// requested but not released, appears nowhere.
func TestInteropClaimsParameter(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	o.login.set(func(a *autoLogin) { a.claims = []string{"email", "name"} })
	r := newRP(t, o, o.issuer, basicClient, oidc.ScopeOpenID)

	claims := xoauth2.SetAuthURLParam("claims",
		`{"id_token":{"email":{"essential":true}},"userinfo":{"name":null,"phone_number":null}}`)

	tok, _, idToken := r.flow(t, claims)

	inToken := claimsOfToken(t, idToken)
	assert.Equal(t, "alice@example.com", inToken["email"])
	assert.NotContains(t, inToken, "name", "requested for UserInfo only")
	assert.NotContains(t, inToken, "phone_number")

	fromUserInfo := r.userInfoClaims(t, tok)
	assert.Equal(t, "Alice Liddell", fromUserInfo["name"])
	assert.NotContains(t, fromUserInfo, "email", "requested for the ID Token only, scope openid alone")
	assert.NotContains(t, fromUserInfo, "phone_number", "not released")
}

// TestInteropConsentNarrowsScope: the end-user grants less than the client
// asked for — no email. The token response names the granted scope (RFC
// 6749 §5.1, §3.3) and go-oidc's UserInfo carries no email claim (OpenID
// Connect Core §5.4).
func TestInteropConsentNarrowsScope(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	o.login.set(func(a *autoLogin) { a.scope = "openid profile" })
	r := newRP(t, o, o.issuer, basicClient)
	require.Equal(t, []string{oidc.ScopeOpenID, "profile", "email"}, r.config.Scopes)

	tok, _, _ := r.flow(t)
	assert.Equal(t, "openid profile", tok.Extra("scope"))

	claims := r.userInfoClaims(t, tok)
	assert.Equal(t, "Alice Liddell", claims["name"])
	assert.NotContains(t, claims, "email")
	assert.NotContains(t, claims, "email_verified")
}

// authTimeOf returns the auth_time of an ID Token go-oidc verified.
func authTimeOf(t *testing.T, idToken *oidc.IDToken) int64 {
	t.Helper()

	var claims struct {
		AuthTime int64 `json:"auth_time"`
	}

	require.NoError(t, idToken.Claims(&claims))
	require.NotZero(t, claims.AuthTime)

	return claims.AuthTime
}

// TestInteropReauthentication pins OpenID Connect Core §3.1.2.1 with
// go-oidc: the browser's session is reused while it satisfies the request
// (same auth_time); prompt=login and max_age=0 make the end-user
// authenticate again (a later auth_time); under prompt=none, a session
// older than max_age comes back to the client as login_required — the
// provider refuses the stale session the application offered.
func TestInteropReauthentication(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	r := newRP(t, o, o.issuer, basicClient)

	_, _, first := r.flow(t)

	o.advance(10 * time.Minute)

	_, _, reused := r.flow(t)
	assert.Equal(t, authTimeOf(t, first), authTimeOf(t, reused), "the session is reused")

	_, _, login := r.flow(t, xoauth2.SetAuthURLParam("prompt", "login"))
	assert.Greater(t, authTimeOf(t, login), authTimeOf(t, first), "prompt=login: authenticated again")

	o.advance(10 * time.Minute)

	_, _, zero := r.flow(t, xoauth2.SetAuthURLParam("max_age", "0"))
	assert.Greater(t, authTimeOf(t, zero), authTimeOf(t, login), "max_age=0: authenticated again")

	o.advance(10 * time.Minute)

	params := r.authorize(t, xoauth2.S256ChallengeOption(xoauth2.GenerateVerifier()), oidc.Nonce(randomNonce()),
		xoauth2.SetAuthURLParam("prompt", "none"), xoauth2.SetAuthURLParam("max_age", "60"))
	assert.Equal(t, "login_required", params.Get("error"))
	assert.Equal(t, "state-1", params.Get("state"))
	assert.Equal(t, o.issuer, params.Get("iss"))
	assert.Empty(t, params.Get("code"))
}

// TestInteropIDTokenHint: an ID Token go-oidc verified, sent back as
// id_token_hint with prompt=none, designates its end-user (OpenID Connect
// Core §3.1.2.1): her session answers silently; once the browser's session
// is another end-user's, the request comes back as login_required — never
// a code for the wrong end-user.
func TestInteropIDTokenHint(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	r := newRP(t, o, o.issuer, basicClient)

	_, raw, first := r.flow(t)

	hint := []xoauth2.AuthCodeOption{xoauth2.SetAuthURLParam("prompt", "none"), xoauth2.SetAuthURLParam("id_token_hint", raw)}

	_, _, again := r.flow(t, hint...)
	assert.Equal(t, first.Subject, again.Subject)

	o.login.set(func(a *autoLogin) { a.subject = "bob" })

	params := r.authorize(t, append(hint, xoauth2.S256ChallengeOption(xoauth2.GenerateVerifier()), oidc.Nonce(randomNonce()))...)
	assert.Equal(t, "login_required", params.Get("error"))
	assert.Empty(t, params.Get("code"))
}

// TestInteropSigningAlgorithms: clients registering an ID Token algorithm
// (Registration §2 id_token_signed_response_alg) get ID Tokens signed with
// the issuer's key of that algorithm, which go-oidc — restricted to that
// algorithm — verifies, at_hash included (Core §3.1.3.6): an independent
// JOSE check of our PS, RS512 and ES signatures.
func TestInteropSigningAlgorithms(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	o.keys.set(o.issuer, algorithmRing())

	for _, alg := range signingAlgorithms {
		t.Run(string(alg), func(t *testing.T) {
			t.Parallel()

			id := signingClientID(alg)
			r := newRP(t, o, o.issuer, clientSpec{id, signingSecret, xoauth2.AuthStyleInHeader})
			r.verifier = r.provider.Verifier(&oidc.Config{ClientID: id, SupportedSigningAlgs: []string{string(alg)}})

			_, raw, idToken := r.flow(t)
			assert.Equal(t, []string{id}, idToken.Audience)

			header := jwsHeader(t, raw)
			assert.Equal(t, string(alg), header["alg"])
			assert.Equal(t, "root-"+strings.ToLower(string(alg)), header["kid"])
		})
	}
}
