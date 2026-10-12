// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// discovery is the part of the discovery document the test uses.
type discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// tokenResponse is a successful token response.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
}

// idClaims are the ID Token claims the test checks.
type idClaims struct {
	Subject  string `json:"sub"`
	Nonce    string `json:"nonce"`
	AuthTime int64  `json:"auth_time"`
	Name     string `json:"name"`
}

// harness is the example served on a loopback port, and a browser.
type harness struct {
	t       *testing.T
	issuer  string
	doc     discovery
	browser *http.Client
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	srv := httptest.NewUnstartedServer(nil)
	issuer := "http://" + srv.Listener.Addr().String()

	handler, err := newServer(issuer)
	require.NoError(t, err)

	srv.Config.Handler = handler
	srv.Start()
	t.Cleanup(srv.Close)

	h := &harness{t: t, issuer: issuer, browser: newBrowser(t)}
	h.getJSON(issuer+"/.well-known/openid-configuration", &h.doc)
	require.Equal(t, issuer, h.doc.Issuer)

	return h
}

// newBrowser is a client with cookies that does not follow redirects.
func newBrowser(t *testing.T) *http.Client {
	t.Helper()

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	return &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (h *harness) do(client *http.Client, method, target string, form url.Values) (*http.Response, string) {
	h.t.Helper()

	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}

	req, err := http.NewRequestWithContext(h.t.Context(), method, target, body)
	require.NoError(h.t, err)

	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := client.Do(req)
	require.NoError(h.t, err)

	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	require.NoError(h.t, err)

	return resp, string(raw)
}

func (h *harness) getJSON(target string, v any) {
	h.t.Helper()

	resp, body := h.do(http.DefaultClient, http.MethodGet, target, nil)
	require.Equal(h.t, http.StatusOK, resp.StatusCode, body)
	require.NoError(h.t, json.Unmarshal([]byte(body), v))
}

// authorizeURL is an authorization request of the confidential client.
func (h *harness) authorizeURL(challenge, nonce string, extra ...string) string {
	q := url.Values{
		"response_type": {"code"}, "client_id": {rpClientID}, "redirect_uri": {rpRedirectURI},
		"scope": {"openid profile email"}, "state": {"st"}, "nonce": {nonce},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}

	for i := 0; i+1 < len(extra); i += 2 {
		q.Set(extra[i], extra[i+1])
	}

	return h.doc.AuthorizationEndpoint + "?" + q.Encode()
}

var hiddenInput = regexp.MustCompile(`name="(csrf_token|return_to)" value="([^"]*)"`)

// formFields returns the hidden fields of a rendered page.
func formFields(t *testing.T, page string) url.Values {
	t.Helper()

	fields := url.Values{}
	for _, m := range hiddenInput.FindAllStringSubmatch(page, -1) {
		fields.Set(m[1], html.UnescapeString(m[2]))
	}

	require.NotEmpty(t, fields.Get("csrf_token"), page)
	require.NotEmpty(t, fields.Get("return_to"), page)

	return fields
}

// redirected returns the parameters of a redirect to the client.
func redirected(t *testing.T, resp *http.Response) url.Values {
	t.Helper()

	require.Equal(t, http.StatusFound, resp.StatusCode)

	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(loc.String(), rpRedirectURI+"?"), loc.String())

	return loc.Query()
}

// signIn runs the login page of an authorization request and returns the
// page the browser lands on afterwards.
func (h *harness) signIn(authorizeURL string) (*http.Response, string) {
	h.t.Helper()

	resp, page := h.do(h.browser, http.MethodGet, authorizeURL, nil)
	require.Equal(h.t, http.StatusOK, resp.StatusCode, page)
	assert.Equal(h.t, "DENY", resp.Header.Get("X-Frame-Options"))
	assert.Equal(h.t, "frame-ancestors 'none'", resp.Header.Get("Content-Security-Policy"))

	fields := formFields(h.t, page)
	fields.Set("username", "alice")
	fields.Set("password", "alice-secret")

	resp, _ = h.do(h.browser, http.MethodPost, h.issuer+"/login", fields)
	require.Equal(h.t, http.StatusSeeOther, resp.StatusCode)
	require.Equal(h.t, fields.Get("return_to"), resp.Header.Get("Location"))

	return h.do(h.browser, http.MethodGet, h.issuer+resp.Header.Get("Location"), nil)
}

// consent answers the consent page.
func (h *harness) consent(page, decision string, offline bool) *http.Response {
	h.t.Helper()

	fields := formFields(h.t, page)
	fields.Set("decision", decision)

	if offline {
		fields.Set("offline_access", "on")
	}

	resp, _ := h.do(h.browser, http.MethodPost, h.issuer+"/consent", fields)
	require.Equal(h.t, http.StatusSeeOther, resp.StatusCode)

	resp, _ = h.do(h.browser, http.MethodGet, h.issuer+resp.Header.Get("Location"), nil)

	return resp
}

// token posts form to the token endpoint as the confidential client.
func (h *harness) token(form url.Values) tokenResponse {
	h.t.Helper()

	req, err := http.NewRequestWithContext(h.t.Context(), http.MethodPost, h.doc.TokenEndpoint, strings.NewReader(form.Encode()))
	require.NoError(h.t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(rpClientID), url.QueryEscape(rpClientSecret))

	resp, err := http.DefaultClient.Do(req)
	require.NoError(h.t, err)

	defer func() { _ = resp.Body.Close() }()

	var out tokenResponse

	require.Equal(h.t, http.StatusOK, resp.StatusCode)
	require.NoError(h.t, json.NewDecoder(resp.Body).Decode(&out))

	return out
}

// verifyIDToken verifies an ID Token as a relying party does: signature
// through the JWK Set, issuer, audience, expiry.
func (h *harness) verifyIDToken(raw string) idClaims {
	h.t.Helper()

	verifier := jwtsec.NewVerifier(jwtsec.NewRemoteJWKS(h.doc.JWKSURI),
		jwtsec.WithIssuer(h.issuer), jwtsec.WithAudience(rpClientID), jwtsec.WithAllowedAlgorithms(jwtsec.RS256))

	var claims idClaims

	_, err := verifier.Verify(h.t.Context(), raw, &claims)
	require.NoError(h.t, err)

	return claims
}

func pkce() (verifier, challenge string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))

	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// TestOpenIDProviderFlow drives the example as a browser and a relying
// party: discovery, login (CSRF), consent with offline access, code,
// tokens, the ID Token verified through the JWK Set, UserInfo, refresh,
// then a silent authentication with the session and the remembered
// consent.
func TestOpenIDProviderFlow(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	verifier, challenge := pkce()

	resp, page := h.signIn(h.authorizeURL(challenge, "n-1",
		"scope", "openid profile email offline_access", "prompt", "consent"))
	require.Equal(t, http.StatusOK, resp.StatusCode, page)
	assert.Contains(t, page, "offline_access", "the consent page offers offline access")

	params := redirected(t, h.consent(page, "allow", true))
	require.Equal(t, "st", params.Get("state"))
	require.Equal(t, h.issuer, params.Get("iss"))

	tokens := h.token(url.Values{
		"grant_type": {"authorization_code"}, "code": {params.Get("code")},
		"redirect_uri": {rpRedirectURI}, "code_verifier": {verifier},
	})
	require.NotEmpty(t, tokens.RefreshToken, "offline access consented")

	claims := h.verifyIDToken(tokens.IDToken)
	assert.Equal(t, "alice", claims.Subject)
	assert.Equal(t, "n-1", claims.Nonce)
	assert.NotZero(t, claims.AuthTime)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, h.doc.UserInfoEndpoint, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)

	userInfo, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	defer func() { _ = userInfo.Body.Close() }()

	var info map[string]any

	require.Equal(t, http.StatusOK, userInfo.StatusCode)
	require.NoError(t, json.NewDecoder(userInfo.Body).Decode(&info))
	assert.Equal(t, "alice", info["sub"])
	assert.Equal(t, "Alice Liddell", info["name"])
	assert.Equal(t, "alice@example.com", info["email"])

	refreshed := h.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}})
	again := h.verifyIDToken(refreshed.IDToken)
	assert.Equal(t, claims.Subject, again.Subject)
	assert.Equal(t, claims.AuthTime, again.AuthTime)

	// The session and the remembered consent answer prompt=none.
	_, challenge = pkce()
	resp, _ = h.do(h.browser, http.MethodGet, h.authorizeURL(challenge, "n-2", "prompt", "none"), nil)
	assert.NotEmpty(t, redirected(t, resp).Get("code"))
}

// TestOpenIDProviderRefusals: no session for prompt=none, a denied
// consent, a forged CSRF token and an open redirect are refused.
func TestOpenIDProviderRefusals(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	_, challenge := pkce()

	resp, _ := h.do(h.browser, http.MethodGet, h.authorizeURL(challenge, "n", "prompt", "none"), nil)
	assert.Equal(t, "login_required", redirected(t, resp).Get("error"))

	resp, page := h.do(h.browser, http.MethodGet, h.authorizeURL(challenge, "n"), nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	fields := formFields(t, page)
	fields.Set("username", "alice")
	fields.Set("password", "alice-secret")

	forged := url.Values{"csrf_token": {"forged"}, "return_to": {fields.Get("return_to")}, "username": {"alice"}, "password": {"alice-secret"}}
	resp, _ = h.do(h.browser, http.MethodPost, h.issuer+"/login", forged)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	elsewhere := url.Values{}
	for k, v := range fields {
		elsewhere[k] = v
	}

	elsewhere.Set("return_to", "https://evil.example/oauth2/authorize?x=1")
	resp, _ = h.do(h.browser, http.MethodPost, h.issuer+"/login", elsewhere)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	wrong := url.Values{}
	for k, v := range fields {
		wrong[k] = v
	}

	wrong.Set("password", "nope")
	resp, _ = h.do(h.browser, http.MethodPost, h.issuer+"/login", wrong)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	resp, _ = h.do(h.browser, http.MethodPost, h.issuer+"/login", fields)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)

	resp, page = h.do(h.browser, http.MethodGet, h.issuer+resp.Header.Get("Location"), nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "the consent page")

	assert.Equal(t, "access_denied", redirected(t, h.consent(page, "deny", false)).Get("error"))
}

// TestOpenIDProviderPromptLogin pins prompt=login through the example's
// own login page: a signed-in end-user signs in again, and the login —
// several HTTP requests — counts from the authorization request.
func TestOpenIDProviderPromptLogin(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	_, challenge := pkce()

	resp, page := h.signIn(h.authorizeURL(challenge, "n"))
	params := redirected(t, h.consent(page, "allow", false))
	require.NotEmpty(t, params.Get("code"), resp.Status)

	resp, page = h.signIn(h.authorizeURL(challenge, "n-again", "prompt", "login"))
	assert.NotEmpty(t, redirected(t, resp).Get("code"), page)
}

// TestAdvertisedURLsAreServed: every URL of the discovery document is
// mounted.
func TestAdvertisedURLsAreServed(t *testing.T) {
	t.Parallel()

	h := newHarness(t)

	var doc map[string]any

	h.getJSON(h.issuer+"/.well-known/openid-configuration", &doc)

	for name, value := range doc {
		endpoint, ok := value.(string)
		if !ok || (!strings.HasSuffix(name, "_endpoint") && name != "jwks_uri") {
			continue
		}

		method, form := http.MethodGet, url.Values(nil)
		if name == "token_endpoint" || name == "revocation_endpoint" || name == "introspection_endpoint" {
			method, form = http.MethodPost, url.Values{}
		}

		resp, _ := h.do(http.DefaultClient, method, endpoint, form)
		assert.NotContains(t, []int{http.StatusNotFound, http.StatusMethodNotAllowed}, resp.StatusCode, "%s %s", name, endpoint)
	}

	var metadata map[string]any

	h.getJSON(h.issuer+"/.well-known/oauth-authorization-server", &metadata)
	assert.Equal(t, h.issuer, metadata["issuer"])
}
