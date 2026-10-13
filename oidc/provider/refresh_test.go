// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider_test

import (
	"crypto/sha256"
	"net/url"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	oidcprovider "github.com/hyperscale-stack/security/oidc/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// offlineQuery requests offline access with the consent dialog §11 asks
// for.
func offlineQuery() url.Values {
	return with(authorizeQuery(), "scope", "openid profile offline_access", "prompt", "consent")
}

// consentOffline makes the interaction grant offline access.
func (e *env) consentOffline() {
	e.decide(func(ev *oidcprovider.AuthenticationEvent) { ev.ACR, ev.AMR = "urn:loa:2", []string{"pwd", "otp"} },
		func(d *oidcprovider.Decision) { d.OfflineAccess = oidcprovider.OfflineAccessPrompted })
}

// TestRefreshIDTokensFollowCore12_2 pins OIDC Core §12.2 through three
// rotations: same iss, sub and aud; iat the time of the refresh; auth_time,
// acr and amr of the original authentication; no nonce; a fresh at_hash.
func TestRefreshIDTokensFollowCore12_2(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	e.consentOffline()

	authTime := e.clock.Now()
	resp := e.flow(offlineQuery())
	require.NotEmpty(t, resp.RefreshToken)

	_, first := e.idToken(resp.IDToken)

	for range 3 {
		e.clock.Advance(time.Hour)

		resp = tokens(t, e.refresh(resp.RefreshToken, ""))
		require.NotEmpty(t, resp.IDToken, "an ID Token at every refresh")

		_, claims := e.idToken(resp.IDToken)
		assert.Equal(t, first["iss"], claims["iss"])
		assert.Equal(t, first["sub"], claims["sub"])
		assert.Equal(t, first["aud"], claims["aud"])
		assert.Equal(t, e.clock.Now().Unix(), unix(t, claims["iat"]))
		assert.Equal(t, authTime.Unix(), unix(t, claims["auth_time"]), "the original authentication time")
		assert.Equal(t, "urn:loa:2", claims["acr"])
		assert.Equal(t, []any{"pwd", "otp"}, claims["amr"])
		assert.NotContains(t, claims, "nonce", "SHOULD NOT have a nonce")
		assert.Equal(t, atHash(sha256.New(), resp.AccessToken), claims["at_hash"])
	}
}

// TestRefreshWithoutOpenIDHasNoIDToken pins §12.2 ("might not contain an
// id_token"): a refresh narrowing the scope without openid gets none.
func TestRefreshWithoutOpenIDHasNoIDToken(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	e.consentOffline()

	resp := e.flow(offlineQuery())
	refreshed := tokens(t, e.refresh(resp.RefreshToken, "profile"))
	assert.Empty(t, refreshed.IDToken)
	assert.Equal(t, "profile", refreshed.Scope)
}

// TestRefreshChecksTheAccountEvenWithoutOpenID (review F1): disabling the
// end-user stops every refresh of an OpenID grant — also one narrowing the
// scope so that no ID Token is issued — and leaves the refresh token
// unconsumed.
func TestRefreshChecksTheAccountEvenWithoutOpenID(t *testing.T) {
	t.Parallel()

	for _, scope := range []string{"", "profile", "offline_access"} {
		e := newEnv(t)
		e.consentOffline()

		resp := e.flow(offlineQuery())
		alice := e.claims.user("alice")
		e.claims.removeUser("alice")

		assert.Equal(t, oauth2.CodeInvalidGrant, oauthError(t, e.refresh(resp.RefreshToken, scope)), "scope %q", scope)

		e.claims.setUser("alice", alice)
		assert.NotEmpty(t, tokens(t, e.refresh(resp.RefreshToken, scope)).AccessToken, "the refresh token stayed usable")
	}
}

// TestRefreshOfAPlainOAuth2Grant: a plain OAuth 2.0 grant whose decision
// grants offline_access refreshes without ID Tokens or account checks.
func TestRefreshOfAPlainOAuth2Grant(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	e.decide(nil, func(d *oidcprovider.Decision) { d.OfflineAccess = oidcprovider.OfflineAccessByPolicy })

	resp := e.flow(with(authorizeQuery(), "scope", "read offline_access", "nonce", ""))
	require.NotEmpty(t, resp.RefreshToken, "RefreshTokenScope satisfied")
	assert.Empty(t, resp.IDToken)

	refreshed := tokens(t, e.refresh(resp.RefreshToken, ""))
	assert.Empty(t, refreshed.IDToken)
	assert.Empty(t, e.claims.recorded(), "no OpenID grant, no account check")
}

// TestRefreshWithoutOfflineConsentFailsClosed (user decision 1): grants
// issuing refresh tokens without RefreshTokenScope would hand OpenID
// clients offline access the end-user never consented to (Core §11); the
// provider refuses the code exchange (server_error: a misconfiguration)
// unless the application allows it explicitly.
func TestRefreshWithoutOfflineConsentFailsClosed(t *testing.T) {
	t.Parallel()

	everyGrant := withGrantConfig(func(g *grant.Config) { g.RefreshTokenScope = "" })

	t.Run("refused by default", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t, everyGrant)
		rec := e.exchange(e.code(authorizeQuery()))
		assert.Equal(t, oauth2.CodeServerError, oauthError(t, rec))
		assert.NotContains(t, rec.Body.String(), "refresh_token")
	})

	t.Run("consented offline access", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t, everyGrant)
		e.consentOffline()

		resp := e.flow(offlineQuery())
		assert.NotEmpty(t, resp.RefreshToken)
		assert.NotEmpty(t, tokens(t, e.refresh(resp.RefreshToken, "")).IDToken)
	})

	t.Run("allowed explicitly", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t, everyGrant, withConfig(func(c *oidcprovider.Config) { c.AllowRefreshWithoutOfflineAccess = true }))

		resp := e.flow(authorizeQuery())
		require.NotEmpty(t, resp.RefreshToken)
		assert.NotEmpty(t, tokens(t, e.refresh(resp.RefreshToken, "")).IDToken)
	})

	t.Run("policy tightened after issuance", func(t *testing.T) {
		t.Parallel()

		store := memory.New()
		lax := newEnv(t, everyGrant, withStore(store), withConfig(func(c *oidcprovider.Config) {
			c.AllowRefreshWithoutOfflineAccess = true
		}))
		resp := lax.flow(authorizeQuery())

		strict := newEnv(t, everyGrant, withStore(store))
		assert.Equal(t, oauth2.CodeInvalidGrant, oauthError(t, strict.refresh(resp.RefreshToken, "")),
			"the grant no longer satisfies the policy: the client must authenticate again")
	})
}
