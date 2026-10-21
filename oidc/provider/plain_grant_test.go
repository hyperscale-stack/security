// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/grant"
	oidcprovider "github.com/hyperscale-stack/security/oidc/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// plainQuery is a plain OAuth 2.0 request of the web client (no openid,
// no nonce) for scope.
func plainQuery(scope string) url.Values {
	return with(authorizeQuery(), "scope", scope, "nonce", "")
}

// TestPlainOAuth2GrantStopsWithItsEndUser: a plain OAuth 2.0 grant the
// provider approved — its Interaction authenticated the end-user — is
// stopped at its next exchange once the ClaimsSource answers
// ErrUnknownSubject (invalid_grant), as an OpenID grant is; another source
// failure answers server_error. Nothing is persisted.
func TestPlainOAuth2GrantStopsWithItsEndUser(t *testing.T) {
	t.Parallel()

	t.Run("code exchange", func(t *testing.T) {
		t.Parallel()

		spy := &spyStore{}
		e := newEnv(t, withSpy(spy))
		code := e.code(plainQuery("read"))

		e.claims.removeUser("alice")
		assert.Equal(t, oauth2.CodeInvalidGrant, oauthError(t, e.exchange(code)))
		assert.Zero(t, spy.pairs.Load(), "nothing is persisted")
	})

	t.Run("refresh", func(t *testing.T) {
		t.Parallel()

		spy := &spyStore{}
		e := newEnv(t, withSpy(spy))
		e.decide(nil, func(d *oidcprovider.Decision) { d.OfflineAccess = oidcprovider.OfflineAccessByPolicy })

		resp := e.flow(plainQuery("read offline_access"))
		require.NotEmpty(t, resp.RefreshToken)

		persisted := spy.pairs.Load()

		e.claims.removeUser("alice")
		assert.Equal(t, oauth2.CodeInvalidGrant, oauthError(t, e.refresh(resp.RefreshToken, "")))
		assert.Equal(t, persisted, spy.pairs.Load(), "nothing is rotated")
	})

	t.Run("claims source failure", func(t *testing.T) {
		t.Parallel()

		spy := &spyStore{}
		e := newEnv(t, withSpy(spy))
		code := e.code(plainQuery("read"))

		e.claims.fail(errors.New("directory down"))
		assert.Equal(t, oauth2.CodeServerError, oauthError(t, e.exchange(code)))
		assert.Zero(t, spy.pairs.Load(), "nothing is persisted")
	})
}

// TestPlainOAuth2GrantKeepsItsRefreshPolicy (OIDC Core §11, "other
// contexts"): the offline-access policy of OpenID grants does not apply to
// a plain OAuth 2.0 grant — its refresh tokens follow RefreshTokenScope,
// here empty: every grant gets one.
func TestPlainOAuth2GrantKeepsItsRefreshPolicy(t *testing.T) {
	t.Parallel()

	e := newEnv(t, withGrantConfig(func(g *grant.Config) { g.RefreshTokenScope = "" }))

	resp := tokens(t, e.exchange(e.code(plainQuery("read"))))
	require.NotEmpty(t, resp.RefreshToken)
	assert.Empty(t, resp.IDToken)
	assert.NotEmpty(t, tokens(t, e.refresh(resp.RefreshToken, "")).AccessToken)
}

// TestForeignConsentPlainGrantIsNotChecked: a plain OAuth 2.0 grant another
// ConsentFunc approved (Server().AuthorizeHandler) names a subject the
// provider's Interaction never authenticated: the ClaimsSource is not asked
// about it.
func TestForeignConsentPlainGrantIsNotChecked(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	approving := e.op.Server().AuthorizeHandler(oauth2.AuthorizeConfig{},
		func(http.ResponseWriter, *http.Request, *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
			return &oauth2.Consent{Approved: true, Subject: "service-account-7"}, nil
		})

	code := redirect(t, serve(approving, get("/oauth2/authorize?"+plainQuery("read offline_access").Encode()))).Get("code")
	resp := tokens(t, e.exchange(code))
	require.NotEmpty(t, resp.RefreshToken)
	require.NotEmpty(t, tokens(t, e.refresh(resp.RefreshToken, "")).AccessToken)
	assert.Empty(t, e.claims.recorded(), "no account check")
}

// TestForgedPlainGrantContextsAreRefused: a plain grant's context holds its
// mark only — a context mixing it with an OpenID member, of an unknown
// version, or on a grant holding openid, is refused (invalid_grant): fail
// closed on what this version did not write.
func TestForgedPlainGrantContextsAreRefused(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, scope, data string
		want              string
	}{
		{"authentication time", "read", `{"v":1,"plain":true,"auth_time":1760000000}`, oauth2.CodeInvalidGrant},
		{"acr", "read", `{"v":1,"plain":true,"acr":"urn:x"}`, oauth2.CodeInvalidGrant},
		{"amr", "read", `{"v":1,"plain":true,"amr":["pwd"]}`, oauth2.CodeInvalidGrant},
		{"empty amr", "read", `{"v":1,"plain":true,"amr":[]}`, oauth2.CodeInvalidGrant},
		{"offline access", "read", `{"v":1,"plain":true,"oa":true}`, oauth2.CodeInvalidGrant},
		{"id_token claims", "read", `{"v":1,"plain":true,"id_token":[{"n":"name"}]}`, oauth2.CodeInvalidGrant},
		{"userinfo claims", "read", `{"v":1,"plain":true,"userinfo":[{"n":"name"}]}`, oauth2.CodeInvalidGrant},
		{"unknown version", "read", `{"v":2,"plain":true}`, oauth2.CodeInvalidGrant},
		{"no mark nor time", "read", `{"v":1,"plain":false}`, oauth2.CodeInvalidGrant},
		{"openid scope", "openid", `{"v":1,"plain":true}`, oauth2.CodeInvalidGrant},
		{"plain grant", "read", `{"v":1,"plain":true}`, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newEnv(t)
			raw := "forged-plain-code-" + tc.name
			now := e.clock.Now()
			require.NoError(t, e.store.SaveAuthorizationCode(context.Background(), &oauth2.AuthorizationCode{
				Code: raw, CodeHash: oauth2.HashToken(nil, raw), ClientID: webClientID, Subject: "alice",
				RedirectURI: webRedirectURI, Scope: tc.scope, CodeChallenge: pkceChallenge, CodeChallengeMethod: "S256",
				IssuedAt: now, ExpiresAt: now.Add(time.Minute), Issuer: testIssuer, ExtensionData: tc.data,
			}))

			rec := e.exchange(raw)
			if tc.want != "" {
				assert.Equal(t, tc.want, oauthError(t, rec))

				return
			}

			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			assert.Len(t, e.claims.recorded(), 1, "one account check")
		})
	}
}
