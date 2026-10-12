// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcrp_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/example/server/storage"
)

// TestZitadelPromptNone sends prompt=none to a provider holding no session
// for the user agent: the provider answers login_required (OpenID Connect
// Core §3.1.2.6), which the client returns as an *AuthorizationError once
// the response is matched to its login — no token request.
func TestZitadelPromptNone(t *testing.T) {
	t.Parallel()

	p := startProvider(t, storage.WebClient(clientID, clientSecret, redirectURL("zitadel")))
	rp := p.relyingParty(t, "zitadel")

	start := httptest.NewRecorder()
	require.NoError(t, rp.StartLogin(start, httptest.NewRequest(http.MethodGet, rpOrigin+"/login", nil),
		oidcclient.AuthOptions{Prompt: []string{"none"}}))

	resp, err := p.agent(t).Get(start.Header().Get("Location"))
	require.NoError(t, err)

	defer func() { _ = resp.Body.Close() }()

	id, err := rp.HandleCallback(httptest.NewRecorder(), callbackRequest(t, resp, start.Result().Cookies()))

	var authErr *oidcclient.AuthorizationError
	require.ErrorAs(t, err, &authErr)
	assert.Equal(t, "login_required", authErr.Code)
	require.ErrorIs(t, err, oidcclient.ErrAuthorizationFailed)
	assert.Nil(t, id)
	assert.Zero(t, p.tokenHits.Load(), "an error response never reaches the token endpoint")
}

// TestZitadelMaxAge sends max_age, which makes auth_time REQUIRED and
// bounds it (Core §3.1.2.1, §3.1.3.7): the provider authenticates the user
// during this login, so the authentication is fresh.
func TestZitadelMaxAge(t *testing.T) {
	t.Parallel()

	p := startProvider(t, storage.WebClient(clientID, clientSecret, redirectURL("zitadel")))
	rp := p.relyingParty(t, "zitadel")

	maxAge := time.Minute
	id, _, err := p.loginWith(t, rp, oidcclient.AuthOptions{MaxAge: &maxAge})
	require.NoError(t, err)
	assert.Contains(t, claimsOf(t, id.Tokens.IDToken), "auth_time")
	assert.WithinDuration(t, time.Now(), id.AuthTime, time.Minute)
}

// TestZitadelACRValues pins a documented interoperability caveat of the
// client: once acr_values are sent, the ID Token MUST carry one of them.
// The example provider ignores acr_values and emits no acr, so the login
// fails closed with ErrIDTokenACR — an application that does not want the
// check sends no acr_values. Without them, the same provider logs in.
func TestZitadelACRValues(t *testing.T) {
	t.Parallel()

	p := startProvider(t, storage.WebClient(clientID, clientSecret, redirectURL("zitadel")))
	rp := p.relyingParty(t, "zitadel")

	id, _, err := p.loginWith(t, rp, oidcclient.AuthOptions{ACRValues: []string{"urn:acr:gold"}})
	require.ErrorIs(t, err, oidcclient.ErrIDTokenACR)
	assert.Nil(t, id)
	assert.Equal(t, int64(1), p.tokenHits.Load(), "the code was redeemed; the ID Token was refused")

	id, _, err = p.login(t, rp)
	require.NoError(t, err)
	assert.NotContains(t, claimsOf(t, id.Tokens.IDToken), "acr", "the provider emits no acr")
	assert.Empty(t, id.ACR)
}
