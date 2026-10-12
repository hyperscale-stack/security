// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcop_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jwtsec "github.com/hyperscale-stack/security/jwt"
	oidcprovider "github.com/hyperscale-stack/security/oidc/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xoauth2 "golang.org/x/oauth2"
)

// TestInteropCodeFlowS256: the whole code flow with S256 PKCE, the client
// authenticated by x/oauth2's client_secret_basic — its ID and secret
// form-encoded (RFC 6749 §2.3.1) — then UserInfo through go-oidc.
func TestInteropCodeFlowS256(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	r := newRP(t, o, o.issuer, basicClient)

	tok, _, idToken := r.flow(t)
	assert.Equal(t, endUser, idToken.Subject)
	assert.Equal(t, []string{basicClientID}, idToken.Audience)
	assert.Equal(t, o.issuer, idToken.Issuer)
	assert.Equal(t, "Bearer", tok.Type())

	info, err := r.provider.UserInfo(r.ctx, xoauth2.StaticTokenSource(tok))
	require.NoError(t, err)
	assert.Equal(t, idToken.Subject, info.Subject)
	assert.Equal(t, "alice@example.com", info.Email)
	assert.True(t, info.EmailVerified)

	var profile struct {
		Name string `json:"name"`
	}

	require.NoError(t, info.Claims(&profile))
	assert.Equal(t, "Alice Liddell", profile.Name)
}

// TestInteropClientSecretPost: x/oauth2's AuthStyleInParams.
func TestInteropClientSecretPost(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	_, _, idToken := newRP(t, o, o.issuer, postClient).flow(t)
	assert.Equal(t, []string{postClientID}, idToken.Audience)
}

// TestInteropPublicClient: a public client, authenticated by PKCE alone.
func TestInteropPublicClient(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	_, _, idToken := newRP(t, o, o.issuer, publicClient).flow(t)
	assert.Equal(t, []string{publicClientID}, idToken.Audience)
}

// TestInteropPathIssuers: path issuers are discovered at their own
// .well-known location (Discovery §4.1), sign with their own keys, and an
// ID Token of one is refused by the other's verifier.
func TestInteropPathIssuers(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	a := newRP(t, o, o.issuer+tenantA, basicClient)
	b := newRP(t, o, o.issuer+tenantB, basicClient)

	assert.Equal(t, o.issuer+tenantA+"/oauth2/authorize", a.provider.Endpoint().AuthURL)

	_, rawA, idA := a.flow(t)
	assert.Equal(t, o.issuer+tenantA, idA.Issuer)

	_, err := b.verifier.Verify(b.ctx, rawA)
	require.Error(t, err, "another issuer")

	var docB struct {
		JWKS string `json:"jwks_uri"`
	}

	require.NoError(t, b.provider.Claims(&docB))

	foreignKeys := oidc.NewVerifier(o.issuer+tenantA, oidc.NewRemoteKeySet(b.ctx, docB.JWKS), &oidc.Config{ClientID: basicClientID})
	_, err = foreignKeys.Verify(b.ctx, rawA)
	require.Error(t, err, "tenant-b does not publish tenant-a's keys")
}

// TestInteropRefresh pins OIDC Core §11 and §12.2 through x/oauth2's token
// source: offline_access consented through prompt=consent gives a refresh
// token, and a refresh a new, verifiable ID Token for the same end-user
// and authentication, without a nonce.
func TestInteropRefresh(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	r := newRP(t, o, o.issuer, basicClient, oidc.ScopeOpenID, "profile", oidc.ScopeOfflineAccess)

	tok, _, first := r.flow(t, xoauth2.SetAuthURLParam("prompt", "consent"))
	require.NotEmpty(t, tok.RefreshToken)

	// A minute later on the provider's clock: the new ID Token is issued
	// then, about the original authentication.
	o.advance(time.Minute)

	expired := *tok
	expired.Expiry = time.Now().Add(-time.Minute)

	refreshed, err := r.config.TokenSource(r.ctx, &expired).Token()
	require.NoError(t, err)
	require.NotEqual(t, tok.AccessToken, refreshed.AccessToken)

	raw, ok := refreshed.Extra("id_token").(string)
	require.True(t, ok, "an ID Token at the refresh")

	second, err := r.verifier.Verify(r.ctx, raw)
	require.NoError(t, err)
	require.NoError(t, second.VerifyAccessToken(refreshed.AccessToken))

	var before, after struct {
		AuthTime int64 `json:"auth_time"`
	}

	require.NoError(t, first.Claims(&before))
	require.NoError(t, second.Claims(&after))
	assert.Equal(t, first.Subject, second.Subject)
	assert.Equal(t, before.AuthTime, after.AuthTime, "the original authentication time")
	assert.GreaterOrEqual(t, second.IssuedAt.Sub(first.IssuedAt), time.Minute, "iat: the time of the refresh")
	assert.Empty(t, second.Nonce)
}

// TestInteropKeyRotation pins OIDC Core §10.1.1 with go-oidc's remote key
// set: a token signed by a new key is verified after a re-fetch, a token of
// the retired key while it stays published, and no longer once removed
// (a fresh verifier: go-oidc keeps a removed key cached until it
// re-fetches).
func TestInteropKeyRotation(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	r := newRP(t, o, o.issuer, basicClient)

	_, oldToken, _ := r.flow(t)

	retired, err := signingKey(0, "root-1").Public()
	require.NoError(t, err)

	o.keys.set(o.issuer, oidcprovider.KeyRing{
		Signing: []jwtsec.PrivateKey{signingKey(1, "root-2")}, Published: []jwtsec.PublicKey{retired},
	})

	_, newToken, _ := r.flow(t)

	_, err = r.verifier.Verify(r.ctx, oldToken)
	require.NoError(t, err, "the retired key is still published")

	o.keys.set(o.issuer, oidcprovider.KeyRing{Signing: []jwtsec.PrivateKey{signingKey(1, "root-2")}})

	fresh := newRP(t, o, o.issuer, basicClient)

	_, err = fresh.verifier.Verify(fresh.ctx, oldToken)
	require.Error(t, err, "the retired key is gone")

	_, err = fresh.verifier.Verify(fresh.ctx, newToken)
	require.NoError(t, err)
}

// TestInteropPromptNone pins OIDC Core §3.1.2.6: without a session,
// prompt=none comes back to the client as login_required, with its state
// and issuer; with one, the code flow completes silently.
func TestInteropPromptNone(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	r := newRP(t, o, o.issuer, basicClient)

	o.login.signedOut.Store(true)

	params := r.authorize(t, xoauth2.S256ChallengeOption(xoauth2.GenerateVerifier()), oidc.Nonce(randomNonce()),
		xoauth2.SetAuthURLParam("prompt", "none"))
	assert.Equal(t, "login_required", params.Get("error"))
	assert.Equal(t, "state-1", params.Get("state"))
	assert.Equal(t, o.issuer, params.Get("iss"))
	assert.Empty(t, params.Get("code"))

	o.login.signedOut.Store(false)

	_, _, idToken := r.flow(t, xoauth2.SetAuthURLParam("prompt", "none"))
	assert.Equal(t, endUser, idToken.Subject)
}

// TestInteropDiscoveryMetadata: what go-oidc reads from the discovery
// document advertises exactly what is served.
func TestInteropDiscoveryMetadata(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	r := newRP(t, o, o.issuer, basicClient)

	var doc struct {
		Issuer                     string   `json:"issuer"`
		ResponseTypes              []string `json:"response_types_supported"`
		ResponseModes              []string `json:"response_modes_supported"`
		SubjectTypes               []string `json:"subject_types_supported"`
		IDTokenAlgs                []string `json:"id_token_signing_alg_values_supported"`
		CodeChallengeMethods       []string `json:"code_challenge_methods_supported"`
		ClaimsParameterSupported   bool     `json:"claims_parameter_supported"`
		RequestParameterSupported  bool     `json:"request_parameter_supported"`
		RequestURIParameter        *bool    `json:"request_uri_parameter_supported"`
		ISSParameterSupported      bool     `json:"authorization_response_iss_parameter_supported"`
		TokenEndpointAuthMethods   []string `json:"token_endpoint_auth_methods_supported"`
		UserInfoEndpoint           string   `json:"userinfo_endpoint"`
		RegistrationEndpointAbsent *string  `json:"registration_endpoint"`
	}

	require.NoError(t, r.provider.Claims(&doc))
	assert.Equal(t, o.issuer, doc.Issuer)
	assert.Equal(t, []string{"code"}, doc.ResponseTypes)
	assert.Equal(t, []string{"query"}, doc.ResponseModes)
	assert.Equal(t, []string{"public"}, doc.SubjectTypes)
	assert.Contains(t, doc.IDTokenAlgs, "RS256")
	assert.Equal(t, []string{"S256"}, doc.CodeChallengeMethods)
	assert.True(t, doc.ClaimsParameterSupported)
	assert.False(t, doc.RequestParameterSupported)
	require.NotNil(t, doc.RequestURIParameter, "its default is true: it must be published")
	assert.False(t, *doc.RequestURIParameter)
	assert.True(t, doc.ISSParameterSupported)
	assert.ElementsMatch(t, []string{"client_secret_basic", "client_secret_post", "none"}, doc.TokenEndpointAuthMethods)
	assert.Equal(t, r.provider.UserInfoEndpoint(), doc.UserInfoEndpoint)
	assert.Nil(t, doc.RegistrationEndpointAbsent)
}

// TestAdvertisedURLsAreServed: every URL the discovery documents advertise
// — and the RFC 8414 metadata of the same issuer — is mounted.
func TestAdvertisedURLsAreServed(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	client := o.srv.Client()

	for _, issuer := range []string{o.issuer, o.issuer + tenantA, o.issuer + tenantB} {
		var doc map[string]any

		getJSON(t, client, issuer+"/.well-known/openid-configuration", &doc)

		for name, value := range doc {
			endpoint, ok := value.(string)
			if !ok || (!strings.HasSuffix(name, "_endpoint") && name != "jwks_uri") {
				continue
			}

			method := http.MethodGet
			if name == "token_endpoint" || name == "revocation_endpoint" || name == "introspection_endpoint" {
				method = http.MethodPost
			}

			req, err := http.NewRequestWithContext(t.Context(), method, endpoint, nil)
			require.NoError(t, err)

			resp, err := client.Do(req)
			require.NoError(t, err)
			_ = resp.Body.Close()

			assert.NotContains(t, []int{http.StatusNotFound, http.StatusMethodNotAllowed}, resp.StatusCode, "%s %s", name, endpoint)
		}

		u, err := url.Parse(issuer)
		require.NoError(t, err)

		var metadata map[string]any

		getJSON(t, client, u.Scheme+"://"+u.Host+"/.well-known/oauth-authorization-server"+u.Path, &metadata)
		assert.Equal(t, issuer, metadata["issuer"])
		assert.Equal(t, doc["token_endpoint"], metadata["token_endpoint"])
	}
}

func getJSON(t *testing.T, client *http.Client, target string, v any) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)

	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode, target)
	require.NoError(t, json.NewDecoder(resp.Body).Decode(v))
}
