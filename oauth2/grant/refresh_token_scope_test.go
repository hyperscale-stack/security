// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grant_test

import (
	"net/url"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/hyperscale-stack/security/oauth2/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scopedCode saves a PKCE-less code granting scope and returns the
// Profile20 request redeeming it.
func scopedCode(t *testing.T, store oauth2.Storage, scope string) grant.Request {
	t.Helper()

	now := time.Now()

	require.NoError(t, store.SaveAuthorizationCode(t.Context(), &oauth2.AuthorizationCode{
		Code: "scoped-code", CodeHash: oauth2.HashToken(nil, "scoped-code"),
		ClientID: clientID, Subject: subject, RedirectURI: redirectURI, Scope: scope,
		IssuedAt: now, ExpiresAt: now.Add(time.Minute), Issuer: issuerA,
	}))

	return grant.Request{
		Client: newClient(), Form: url.Values{"code": {"scoped-code"}, "redirect_uri": {redirectURI}},
		Issuer: issuerA, Now: now, Profile: oauth2.Profile20,
	}
}

// TestRefreshTokenScopeGatesTheCodeExchange: with RefreshTokenScope set,
// the code exchange issues a refresh token only when the granted scope
// holds that exact scope token — e.g. offline_access (OpenID Connect Core
// §11); unset, it issues one whenever it has a generator, as before.
func TestRefreshTokenScopeGatesTheCodeExchange(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, gate, scope string
		generator         bool
		wantRefresh       bool
	}{
		{"gate unset", "", "openid", true, true},
		{"scope granted", "offline_access", "openid offline_access", true, true},
		{"scope not granted", "offline_access", "openid", true, false},
		{"prefix only", "offline_access", "openid offline", true, false},
		{"longer token", "offline_access", "openid offline_access_2", true, false},
		{"no generator", "offline_access", "openid offline_access", false, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := memory.New()
			cfg := grantConfig(store)
			cfg.RefreshTokenScope = tc.gate

			if !tc.generator {
				cfg.RefreshTokens = nil
			}

			resp, err := grant.NewAuthorizationCode(cfg).Handle(t.Context(), scopedCode(t, store, tc.scope))
			require.NoError(t, err)
			assert.Equal(t, tc.wantRefresh, resp.Pair.Refresh != nil)

			_, err = store.LookupAccessToken(t.Context(), resp.Pair.Access.TokenHash)
			require.NoError(t, err, "the access token is issued either way")
		})
	}
}

// TestRefreshTokenScopeGatesThePasswordGrant: the legacy password grant
// follows the same rule.
func TestRefreshTokenScopeGatesThePasswordGrant(t *testing.T) {
	t.Parallel()

	cfg := grantConfig(memory.New())
	cfg.RefreshTokenScope = "admin"

	g := grant.NewLegacyPassword(cfg, staticVerifier{})

	for scope, wantRefresh := range map[string]bool{"read:mail admin": true, "read:mail": false} {
		resp, err := g.Handle(t.Context(), grant.Request{
			Client: newClient(), Issuer: issuerA, Now: time.Now(), Profile: oauth2.Profile20,
			Form: url.Values{"username": {"alice"}, "password": {"pw"}, "scope": {scope}},
		})
		require.NoError(t, err)
		assert.Equal(t, wantRefresh, resp.Pair.Refresh != nil, scope)
	}
}

// TestRefreshTokenScopeLeavesRotationAlone: a refresh token issued under
// the gate keeps rotating, its replacement keeping its scope (RFC 6749
// §6), even when the refresh narrows the access token's scope below the
// gate.
func TestRefreshTokenScopeLeavesRotationAlone(t *testing.T) {
	t.Parallel()

	store := memory.New()
	cfg := grantConfig(store)
	cfg.RefreshTokenScope = "offline_access"
	cfg.RefreshTokens = token.OpaqueRefreshAdapter{Opaque: token.NewOpaque(32)}

	code, err := grant.NewAuthorizationCode(cfg).Handle(t.Context(), scopedCode(t, store, "read:mail offline_access"))
	require.NoError(t, err)
	require.NotNil(t, code.Pair.Refresh)

	req := refreshRequest(code.Pair.Refresh.Token, issuerA)
	req.Form.Set("scope", "read:mail")

	resp, err := grant.NewRefreshToken(cfg).Handle(t.Context(), req)
	require.NoError(t, err)
	require.NotNil(t, resp.Pair.Refresh)
	assert.Equal(t, "read:mail offline_access", resp.Pair.Refresh.Scope)
	assert.Equal(t, "read:mail", resp.Pair.Access.Scope)
}
