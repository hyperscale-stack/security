// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExampleOAuth2EndToEnd(t *testing.T) {
	t.Parallel()

	handler, err := buildServer()
	require.NoError(t, err)

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	// 1. The authorization server mints an access token over client_credentials.
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", "api:read")

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/oauth2/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(demoClientID, demoClientSecret)

	resp, err := srv.Client().Do(req)
	require.NoError(t, err)

	var token struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&token))
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NotEmpty(t, token.AccessToken)

	// 2. The protected resource accepts the issued token.
	probe, err := http.NewRequest(http.MethodGet, srv.URL+"/protected", nil)
	require.NoError(t, err)
	probe.Header.Set("Authorization", "Bearer "+token.AccessToken)

	resp, err = srv.Client().Do(probe)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), "hello")

	// 3. The protected resource rejects a request with no token.
	resp, err = srv.Client().Get(srv.URL + "/protected")
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// 4. The metadata document is served.
	resp, err = srv.Client().Get(srv.URL + "/.well-known/oauth-authorization-server")
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// 5. The public route needs no authentication.
	resp, err = srv.Client().Get(srv.URL + "/")
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// RFC 7636 Appendix B sample PKCE pair.
const (
	pkceVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	pkceChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

// TestExampleOAuth2AuthorizationCodeFlow drives the browser flow: the
// consent page, the approval redirect carrying the code, and the code
// exchange at /token.
func TestExampleOAuth2AuthorizationCodeFlow(t *testing.T) {
	t.Parallel()

	handler, err := buildServer()
	require.NoError(t, err)

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse // inspect the redirect rather than follow it
	}

	authz := url.Values{
		"response_type":         {"code"},
		"client_id":             {demoClientID},
		"redirect_uri":          {"http://localhost:1337/callback"},
		"scope":                 {"api:read"},
		"state":                 {"demo-state"},
		"code_challenge":        {pkceChallenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	// 1. GET /authorize renders the consent page.
	resp, err := client.Get(srv.URL + "/oauth2/authorize?" + authz)
	require.NoError(t, err)
	page, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(page), "Approve")

	// 2. Approving redirects to the callback with an authorization code.
	resp, err = client.PostForm(srv.URL+"/oauth2/authorize?"+authz, url.Values{"decision": {"approve"}})
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)

	code := loc.Query().Get("code")
	require.NotEmpty(t, code)
	assert.Equal(t, "demo-state", loc.Query().Get("state"))

	// 3. The code is exchanged for an access token at /token.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://localhost:1337/callback"},
		"code_verifier": {pkceVerifier},
	}

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/oauth2/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(demoClientID, demoClientSecret)

	resp, err = client.Do(req)
	require.NoError(t, err)

	var tok struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tok))
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.NotEmpty(t, tok.AccessToken)
}
