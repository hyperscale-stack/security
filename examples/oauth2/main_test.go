// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
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
		"redirect_uri":          {"http://127.0.0.1:1337/callback"},
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

	// 2. Approving redirects to the callback with an authorization code —
	// 303 See Other: the answer to a POST (RFC 9700 §4.12).
	resp, err = client.PostForm(srv.URL+"/oauth2/authorize?"+authz, url.Values{"decision": {"approve"}})
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)

	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)

	code := loc.Query().Get("code")
	require.NotEmpty(t, code)
	assert.Equal(t, "demo-state", loc.Query().Get("state"))

	// 3. The code is exchanged for an access token at /token.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://127.0.0.1:1337/callback"},
		"code_verifier": {pkceVerifier},
	}

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/oauth2/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(demoClientID, demoClientSecret)

	resp, err = client.Do(req)
	require.NoError(t, err)

	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tok))
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.NotEmpty(t, tok.AccessToken)
	require.NotEmpty(t, tok.RefreshToken)

	// 4. Profile20BCP mandates refresh-token rotation: the refresh exchange
	// returns a replacement refresh token...
	resp = refreshExchange(t, client, srv.URL, tok.RefreshToken)

	var rotated struct {
		RefreshToken string `json:"refresh_token"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&rotated))
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NotEmpty(t, rotated.RefreshToken)
	assert.NotEqual(t, tok.RefreshToken, rotated.RefreshToken)

	// 5. ...and replaying the consumed one is refused.
	resp = refreshExchange(t, client, srv.URL, tok.RefreshToken)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// refreshExchange POSTs a refresh_token grant for raw to the demo /token
// endpoint, authenticated as the demo client.
func refreshExchange(t *testing.T, client *http.Client, baseURL, raw string) *http.Response {
	t.Helper()

	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {raw}}

	req, err := http.NewRequest(http.MethodPost, baseURL+"/oauth2/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(demoClientID, demoClientSecret)

	resp, err := client.Do(req)
	require.NoError(t, err)

	return resp
}

// TestExampleConsentIsProtected drives the consent page the way a browser
// does: the page cannot be framed nor cached, a decision posted from another
// site is refused (RFC 6749 §10.12) and issues nothing, while an
// authorization request posted from another site — which RFC 6749 §3.1 and
// OpenID Connect allow — still shows the consent page.
func TestExampleConsentIsProtected(t *testing.T) {
	t.Parallel()

	handler, err := buildServer()
	require.NoError(t, err)

	authz := url.Values{
		"response_type":         {"code"},
		"client_id":             {demoClientID},
		"redirect_uri":          {"http://127.0.0.1:1337/callback"},
		"scope":                 {"api:read"},
		"state":                 {"demo-state"},
		"code_challenge":        {pkceChallenge},
		"code_challenge_method": {"S256"},
	}

	serve := func(req *http.Request) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		return rec
	}
	post := func(form url.Values, site string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/oauth2/authorize?"+authz.Encode(), strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", site)

		return req
	}

	page := serve(httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+authz.Encode(), nil))
	require.Equal(t, http.StatusOK, page.Code)
	assert.Equal(t, "DENY", page.Header().Get("X-Frame-Options"))
	assert.Contains(t, page.Header().Values("Content-Security-Policy"), "frame-ancestors 'none'")
	assert.Equal(t, "no-store", page.Header().Get("Cache-Control"))
	assert.Equal(t, "same-origin", page.Header().Get("Referrer-Policy"))

	forged := serve(post(url.Values{"decision": {"approve"}}, "cross-site"))
	assert.Equal(t, http.StatusForbidden, forged.Code, "a cross-site decision is refused")
	assert.Empty(t, forged.Header().Get("Location"), "no code")

	request := serve(post(url.Values{}, "cross-site"))
	assert.Equal(t, http.StatusOK, request.Code, "a cross-site authorization request shows the consent page")
	assert.Contains(t, request.Body.String(), "Approve")

	approved := serve(post(url.Values{"decision": {"approve"}}, "same-origin"))
	require.Equal(t, http.StatusSeeOther, approved.Code)

	loc, err := url.Parse(approved.Header().Get("Location"))
	require.NoError(t, err)
	assert.NotEmpty(t, loc.Query().Get("code"))
}

// consentForm extracts the action and the hidden fields of the consent
// page's form, as a browser submits them.
func consentForm(t *testing.T, page string) (string, url.Values) {
	t.Helper()

	action := regexp.MustCompile(`<form method="post" action="([^"]*)">`).FindStringSubmatch(page)
	require.Len(t, action, 2, page)

	fields := url.Values{}
	for _, m := range regexp.MustCompile(`<input type="hidden" name="([^"]*)" value="([^"]*)">`).FindAllStringSubmatch(page, -1) {
		fields.Add(html.UnescapeString(m[1]), html.UnescapeString(m[2]))
	}

	return html.UnescapeString(action[1]), fields
}

// TestExampleConsentKeepsABodyPostedRequest: an authorization request
// POSTed with its parameters in the body (RFC 6749 §3.1, OpenID Connect
// Core §3.1.2.1) gets a consent page whose form posts the request back
// with the decision, so the approval issues a code.
func TestExampleConsentKeepsABodyPostedRequest(t *testing.T) {
	t.Parallel()

	handler, err := buildServer()
	require.NoError(t, err)

	authz := url.Values{
		"response_type":         {"code"},
		"client_id":             {demoClientID},
		"redirect_uri":          {"http://127.0.0.1:1337/callback"},
		"scope":                 {"api:read"},
		"state":                 {"demo-state"},
		"code_challenge":        {pkceChallenge},
		"code_challenge_method": {"S256"},
	}

	post := func(target string, form url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "same-origin")

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		return rec
	}

	withEmptyDecision := url.Values{"decision": {""}}
	for k, v := range authz {
		withEmptyDecision[k] = v
	}

	// An empty decision in the request is no decision: the page must not
	// post it back ahead of the button's.
	for name, request := range map[string]url.Values{"request": authz, "request with an empty decision": withEmptyDecision} {
		page := post("/oauth2/authorize", request)
		require.Equal(t, http.StatusOK, page.Code, name)

		action, fields := consentForm(t, page.Body.String())
		assert.NotContains(t, fields, "decision", name)
		fields.Add("decision", "approve")

		approved := post(action, fields)
		require.Equal(t, http.StatusSeeOther, approved.Code, "%s: %s", name, approved.Body.String())

		loc, err := url.Parse(approved.Header().Get("Location"))
		require.NoError(t, err)
		assert.NotEmpty(t, loc.Query().Get("code"), name)
		assert.Equal(t, "demo-state", loc.Query().Get("state"), name)
	}
}
