// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	"context"
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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	jwtsec "github.com/hyperscale-stack/security/jwt"
	oidcprovider "github.com/hyperscale-stack/security/oidc/provider"
	"github.com/hyperscale-stack/security/outbound"
	"github.com/hyperscale-stack/security/password"
	"github.com/hyperscale-stack/security/session"
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

	handler, err := newServer(config{Issuer: issuer, RedirectURI: defaultRedirectURI})
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
		"response_type": {"code"}, "client_id": {rpClientID}, "redirect_uri": {defaultRedirectURI},
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
	require.True(t, strings.HasPrefix(loc.String(), defaultRedirectURI+"?"), loc.String())

	return loc.Query()
}

// signIn runs the login page of an authorization request and returns the
// page the browser lands on afterwards.
func (h *harness) signIn(authorizeURL string) (*http.Response, string) {
	h.t.Helper()

	resp, page := h.do(h.browser, http.MethodGet, authorizeURL, nil)
	require.Equal(h.t, http.StatusOK, resp.StatusCode, page)
	assertPageHeaders(h.t, resp)

	fields := formFields(h.t, page)
	fields.Set("username", "alice")
	fields.Set("password", "alice-secret")

	resp, _ = h.do(h.browser, http.MethodPost, h.issuer+"/login", fields)
	require.Equal(h.t, http.StatusSeeOther, resp.StatusCode)
	require.Equal(h.t, fields.Get("return_to"), resp.Header.Get("Location"))

	resp, page = h.do(h.browser, http.MethodGet, h.issuer+resp.Header.Get("Location"), nil)
	if resp.StatusCode == http.StatusOK {
		assertPageHeaders(h.t, resp) // the consent page
	}

	return resp, page
}

// assertPageHeaders asserts the headers of the login and consent pages:
// never framed (clickjacking), never cached.
func assertPageHeaders(t *testing.T, resp *http.Response) {
	t.Helper()

	assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))
	assert.Equal(t, "frame-ancestors 'none'", resp.Header.Get("Content-Security-Policy"))
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
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

	// The example runs on loopback over http: the JWK Set fetch needs an
	// explicit outbound policy (the default refuses both).
	keys, err := jwtsec.NewRemoteJWKS(h.doc.JWKSURI, jwtsec.WithOutboundPolicy(outbound.Policy{
		AllowHTTP: true, AllowedPrefixes: outbound.LoopbackPrefixes(),
	}))
	require.NoError(h.t, err)

	verifier := jwtsec.NewVerifier(keys,
		jwtsec.WithIssuer(h.issuer), jwtsec.WithAudience(rpClientID), jwtsec.WithAllowedAlgorithms(jwtsec.RS256))

	var claims idClaims

	_, err = verifier.Verify(h.t.Context(), raw, &claims)
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
		"redirect_uri": {defaultRedirectURI}, "code_verifier": {verifier},
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

// TestOpenIDProviderPendingLoginIsBoundToTheBrowser (code review F10): the
// start of a pending login is bound to the browser — whoever knows the
// parameters of an authorization request cannot backdate its start for
// another browser, to have a session older than the request pass
// prompt=login.
func TestOpenIDProviderPendingLoginIsBoundToTheBrowser(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	_, challenge := pkce()
	target := h.authorizeURL(challenge, "n-target", "prompt", "login")

	// Another browser opens the login page of the target request first.
	resp, _ := h.do(newBrowser(t), http.MethodGet, target, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// The end-user then signs in for another request, and consents.
	_, other := pkce()
	_, page := h.signIn(h.authorizeURL(other, "n-other"))
	require.NotEmpty(t, redirected(t, h.consent(page, "allow", false)).Get("code"))

	// Their session predates the target request: prompt=login shows the
	// login page instead of issuing a code.
	resp, page = h.do(h.browser, http.MethodGet, target, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "the login page, not a redirect")
	assert.Contains(t, page, `action="/login"`)
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

// TestLoadConfig: the defaults pair the example with examples/oidc-client;
// the environment overrides them; a redirect URI the provider's profile
// refuses — not absolute, with a fragment (RFC 6749 §3.1.2), or http but on
// a loopback IP literal (RFC 9700 §2.6: localhost included) — is refused at
// startup.
func TestLoadConfig(t *testing.T) {
	t.Setenv("OIDC_PROVIDER_ISSUER", "")
	t.Setenv("OIDC_PROVIDER_ADDR", "")
	t.Setenv("OIDC_PROVIDER_REDIRECT_URI", "")

	cfg, err := loadConfig()
	require.NoError(t, err)
	assert.Equal(t, config{
		Issuer: "http://localhost:8083", Addr: "localhost:8083", RedirectURI: "http://127.0.0.1:9000/oidc/demo/callback",
	}, cfg)

	t.Setenv("OIDC_PROVIDER_ISSUER", "http://127.0.0.1:8083")
	t.Setenv("OIDC_PROVIDER_ADDR", "127.0.0.1:8083")
	t.Setenv("OIDC_PROVIDER_REDIRECT_URI", "http://[::1]:9000/oidc/e2e/callback")

	cfg, err = loadConfig()
	require.NoError(t, err)
	assert.Equal(t, config{
		Issuer: "http://127.0.0.1:8083", Addr: "127.0.0.1:8083", RedirectURI: "http://[::1]:9000/oidc/e2e/callback",
	}, cfg)

	for _, bad := range []string{
		"/oidc/demo/callback", "http:///oidc/demo/callback", "ftp://localhost/cb",
		"http://127.0.0.1:9000/cb#fragment", "http://127.0.0.1:9000/cb#", "%zz",
		"http://localhost:9000/oidc/demo/callback", "http://rp.example/oidc/demo/callback",
	} {
		t.Setenv("OIDC_PROVIDER_REDIRECT_URI", bad)

		_, err := loadConfig()
		require.ErrorContains(t, err, "OIDC_PROVIDER_REDIRECT_URI", bad)
	}
}

// TestConfiguredRedirectURI: both clients are registered with the
// configured redirect URI only — the default one is then refused without
// a redirect — and an https issuer gets Secure session cookies.
func TestConfiguredRedirectURI(t *testing.T) {
	t.Parallel()

	const custom = "https://rp.example/oidc/demo/callback"

	handler, err := newServer(config{Issuer: "https://op.example", RedirectURI: custom})
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://op.example/.well-known/openid-configuration", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	var doc discovery
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &doc))

	_, challenge := pkce()

	authorize := func(redirectURI string) *httptest.ResponseRecorder {
		q := url.Values{
			"response_type": {"code"}, "client_id": {rpClientID}, "redirect_uri": {redirectURI}, "scope": {"openid"},
			"state": {"st"}, "nonce": {"n"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
		}

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, doc.AuthorizationEndpoint+"?"+q.Encode(), nil))

		return rec
	}

	login := authorize(custom)
	require.Equal(t, http.StatusOK, login.Code, "the login page")

	cookies := login.Result().Cookies()
	require.NotEmpty(t, cookies)

	for _, c := range cookies {
		assert.True(t, c.Secure, c.Name)
	}

	refused := authorize(defaultRedirectURI)
	assert.Equal(t, http.StatusBadRequest, refused.Code)
	assert.Empty(t, refused.Header().Get("Location"))
}

// plainURL is a plain OAuth 2.0 authorization request (no openid) of the
// confidential client.
func (h *harness) plainURL(challenge, scope string) string {
	q := url.Values{
		"response_type": {"code"}, "client_id": {rpClientID}, "redirect_uri": {defaultRedirectURI},
		"scope": {scope}, "state": {"st-plain"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}

	return h.doc.AuthorizationEndpoint + "?" + q.Encode()
}

// exchange redeems the code of a redirect with verifier.
func (h *harness) exchange(resp *http.Response, verifier string) tokenResponse {
	h.t.Helper()

	return h.token(url.Values{
		"grant_type": {"authorization_code"}, "code": {redirected(h.t, resp).Get("code")},
		"redirect_uri": {defaultRedirectURI}, "code_verifier": {verifier},
	})
}

// offersOffline reports whether a consent page offers offline access.
func offersOffline(page string) bool { return strings.Contains(page, `name="offline_access"`) }

// TestOfflineAccessNeedsTheEndUsersChoice: the example grants offline
// access — a 30-day refresh token — on the end-user's explicit choice
// only, for OpenID and plain OAuth 2.0 requests alike: the consent page
// offers it whenever it can be granted, never from a consent remembered
// earlier (OIDC Core §11), and an unticked box drops offline_access.
func TestOfflineAccessNeedsTheEndUsersChoice(t *testing.T) {
	t.Parallel()

	t.Run("declined, then requested by a plain request", func(t *testing.T) {
		t.Parallel()

		h := newHarness(t)
		verifier, challenge := pkce()
		_, page := h.signIn(h.authorizeURL(challenge, "n-1", "scope", "openid profile offline_access", "prompt", "consent"))
		require.True(t, offersOffline(page))

		first := h.exchange(h.consent(page, "allow", false), verifier)
		assert.Empty(t, first.RefreshToken, "offline access declined")

		verifier, challenge = pkce()
		resp, page := h.do(h.browser, http.MethodGet, h.plainURL(challenge, "profile offline_access"), nil)
		require.Equal(t, http.StatusOK, resp.StatusCode, "the consent page, not a silent code")
		require.True(t, offersOffline(page))

		second := h.exchange(h.consent(page, "allow", false), verifier)
		assert.Equal(t, "profile", second.Scope)
		assert.Empty(t, second.RefreshToken)
	})

	t.Run("granted by a plain request, then asked again", func(t *testing.T) {
		t.Parallel()

		h := newHarness(t)
		verifier, challenge := pkce()
		resp, page := h.signIn(h.plainURL(challenge, "profile offline_access"))
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.True(t, offersOffline(page), "a plain request is offered the choice")

		tokens := h.exchange(h.consent(page, "allow", true), verifier)
		assert.Equal(t, "profile offline_access", tokens.Scope)
		assert.NotEmpty(t, tokens.RefreshToken, "offline access ticked")

		_, challenge = pkce()
		resp, page = h.do(h.browser, http.MethodGet, h.plainURL(challenge, "profile offline_access"), nil)
		assert.Equal(t, http.StatusOK, resp.StatusCode, "offline access is never remembered")
		assert.True(t, offersOffline(page))
	})

	t.Run("only offline access requested, declined", func(t *testing.T) {
		t.Parallel()

		h := newHarness(t)
		_, challenge := pkce()
		_, page := h.signIn(h.plainURL(challenge, "offline_access"))

		assert.Equal(t, "access_denied", redirected(t, h.consent(page, "allow", false)).Get("error"))
	})

	t.Run("OpenID request without prompt=consent", func(t *testing.T) {
		t.Parallel()

		h := newHarness(t)
		verifier, challenge := pkce()
		_, page := h.signIn(h.authorizeURL(challenge, "n-1", "scope", "openid offline_access"))
		assert.False(t, offersOffline(page), "Core §11: prompt=consent is required")

		tokens := h.exchange(h.consent(page, "allow", true), verifier)
		assert.Empty(t, tokens.RefreshToken, "a box the page did not offer grants nothing")
	})
}

// TestRememberedConsentCoversOnlyWhatWasShown: a consent is remembered for
// the scopes and claims the end-user saw — a later request of the client
// asking for more shows the page again (or, under prompt=none, answers
// consent_required); prompt=consent always shows it.
func TestRememberedConsentCoversOnlyWhatWasShown(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	_, challenge := pkce()
	_, page := h.signIn(h.authorizeURL(challenge, "n-1", "scope", "openid"))
	require.NotEmpty(t, redirected(t, h.consent(page, "allow", false)).Get("code"))

	moreClaims := []string{"scope", "openid", "claims", `{"id_token":{"name":null}}`}

	verifier, challenge := pkce()
	resp, page := h.do(h.browser, http.MethodGet, h.authorizeURL(challenge, "n-2", moreClaims...), nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "new claims: the consent page")
	assert.Contains(t, page, "name")

	claims := h.verifyIDToken(h.exchange(h.consent(page, "allow", false), verifier).IDToken)
	assert.Equal(t, "Alice Liddell", claims.Name)

	_, challenge = pkce()
	resp, _ = h.do(h.browser, http.MethodGet, h.authorizeURL(challenge, "n-3", moreClaims...), nil)
	assert.NotEmpty(t, redirected(t, resp).Get("code"), "what was shown is remembered")

	_, challenge = pkce()
	resp, _ = h.do(h.browser, http.MethodGet, h.authorizeURL(challenge, "n-4", "scope", "openid email"), nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "a new scope: the consent page")

	_, challenge = pkce()
	resp, _ = h.do(h.browser, http.MethodGet, h.authorizeURL(challenge, "n-5", "scope", "openid", "prompt", "none",
		"claims", `{"userinfo":{"email":null}}`), nil)
	assert.Equal(t, "consent_required", redirected(t, resp).Get("error"))

	_, challenge = pkce()
	resp, _ = h.do(h.browser, http.MethodGet, h.authorizeURL(challenge, "n-6", "scope", "openid", "prompt", "consent"), nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "prompt=consent always shows the page")
}

// TestConsentAnswerAppliesToTheRequestShown: the answer given on a consent
// page applies to the very request it showed — not to another request of
// the client that shares its client_id, state, nonce and code_challenge
// but asks for more.
func TestConsentAnswerAppliesToTheRequestShown(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	_, challenge := pkce()
	_, page := h.signIn(h.authorizeURL(challenge, "n-1", "scope", "openid"))

	fields := formFields(t, page)
	fields.Set("decision", "allow")
	resp, _ := h.do(h.browser, http.MethodPost, h.issuer+"/consent", fields)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)

	resp, page = h.do(h.browser, http.MethodGet, h.authorizeURL(challenge, "n-1", "scope", "openid email"), nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "the consent page, not a code: %s", page)
}

// TestConsentEndpointRefusals: the consent endpoint refuses a forged CSRF
// token — recording nothing — and a return address that is not this
// provider's authorization endpoint (no open redirect).
func TestConsentEndpointRefusals(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	_, challenge := pkce()
	_, page := h.signIn(h.authorizeURL(challenge, "n"))
	fields := formFields(t, page)
	fields.Set("decision", "allow")

	forged := url.Values{}
	for k, v := range fields {
		forged[k] = v
	}

	forged.Set("csrf_token", "forged")
	resp, _ := h.do(h.browser, http.MethodPost, h.issuer+"/consent", forged)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	resp, _ = h.do(h.browser, http.MethodGet, h.issuer+fields.Get("return_to"), nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "nothing was recorded: the consent page again")

	for _, target := range []string{
		"https://evil.example/oauth2/authorize?x=1", "//evil.example/oauth2/authorize", "/login?x=1",
	} {
		elsewhere := url.Values{}
		for k, v := range fields {
			elsewhere[k] = v
		}

		elsewhere.Set("return_to", target)
		resp, _ := h.do(h.browser, http.MethodPost, h.issuer+"/consent", elsewhere)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, target)
	}
}

// testClock is the injectable clock of the provider and the application.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = c.now.Add(d)
}

// pendingCount returns the authorization requests in progress the
// application holds.
func (a *app) pendingCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()

	return len(a.pending)
}

// TestPendingRequestsAreBounded: every authorization request of a browser
// without a session opens a login page and leaves server-side state; the
// application holds at most its limit of them, and purges those older than
// oidcprovider.MaxInteractionDuration — however many requests come.
func TestPendingRequestsAreBounded(t *testing.T) {
	t.Parallel()

	const issuer = "http://127.0.0.1:1"

	clock := &testClock{now: time.Now()}
	handler, a, err := buildServer(config{Issuer: issuer, RedirectURI: defaultRedirectURI}, clock.Now)
	require.NoError(t, err)

	a.pendingLimit = 50

	request := func(i int) {
		t.Helper()

		_, challenge := pkce()
		q := url.Values{
			"response_type": {"code"}, "client_id": {rpClientID}, "redirect_uri": {defaultRedirectURI},
			"scope": {"openid"}, "state": {strconv.Itoa(i)}, "nonce": {"n"},
			"code_challenge": {challenge}, "code_challenge_method": {"S256"},
		}

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, issuer+"/oauth2/authorize?"+q.Encode(), nil))
		require.Equal(t, http.StatusOK, rec.Code, "the login page")
	}

	for i := range 200 {
		request(i)
	}

	assert.LessOrEqual(t, a.pendingCount(), 50, "at most the limit")

	clock.Advance(oidcprovider.MaxInteractionDuration + time.Minute)
	request(200)
	assert.Equal(t, 1, a.pendingCount(), "the expired ones are purged")
}

// countingHasher records the hashes the login compares a password with.
type countingHasher struct {
	password.Hasher

	mu     sync.Mutex
	hashes []string
}

func (c *countingHasher) Verify(ctx context.Context, encodedHash, pass string) (bool, error) {
	c.mu.Lock()
	c.hashes = append(c.hashes, encodedHash)
	c.mu.Unlock()

	return c.Hasher.Verify(ctx, encodedHash, pass) //nolint:wrapcheck // test double
}

// TestUnknownUsernamesCostAPasswordVerification: every login attempt costs
// one password-hash comparison of the same cost — an unknown username is
// compared with a dummy hash — so that the response time does not tell
// whether an account exists.
func TestUnknownUsernamesCostAPasswordVerification(t *testing.T) {
	t.Parallel()

	_, a, err := buildServer(config{Issuer: "http://127.0.0.1:1", RedirectURI: defaultRedirectURI}, time.Now)
	require.NoError(t, err)

	counting := &countingHasher{Hasher: a.hasher}
	a.hasher = counting

	assert.False(t, a.verifyPassword(t.Context(), "nobody", "alice-secret"))
	assert.False(t, a.verifyPassword(t.Context(), "alice", "wrong"))
	assert.True(t, a.verifyPassword(t.Context(), "alice", "alice-secret"))

	require.Len(t, counting.hashes, 3, "one comparison per attempt, known username or not")
	assert.NotEqual(t, counting.hashes[1], counting.hashes[0], "an unknown username is compared with a dummy hash")
	assert.False(t, counting.NeedsRehash(counting.hashes[0]), "of the cost of real hashes")
}

// TestHTTPServerHasTimeouts: the demo server bounds the time a client may
// take to send its request and to read the response, and how long an idle
// connection stays open.
func TestHTTPServerHasTimeouts(t *testing.T) {
	t.Parallel()

	srv := newHTTPServer("localhost:0", http.NotFoundHandler())
	assert.Positive(t, srv.ReadHeaderTimeout)
	assert.Positive(t, srv.ReadTimeout)
	assert.Positive(t, srv.WriteTimeout)
	assert.Positive(t, srv.IdleTimeout)
}

// TestDocumentsAreServedAtTheirPathsOnly: the discovery document and the
// JWK Set are mounted exactly at their Paths — the provider's handlers do
// not check the request path, and relying parties require the issuer to be
// the URL they fetched the document from (Discovery §4.3).
func TestDocumentsAreServedAtTheirPathsOnly(t *testing.T) {
	t.Parallel()

	h := newHarness(t)

	for _, path := range []string{
		"/tenant/.well-known/openid-configuration", "/.well-known/openid-configuration/x", "/x/.well-known/jwks.json",
	} {
		resp, _ := h.do(http.DefaultClient, http.MethodGet, h.issuer+path, nil)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode, path)
	}
}

// TestPendingRequestsExpire: a login start or a consent answer unused for
// oidcprovider.MaxInteractionDuration no longer counts.
func TestPendingRequestsExpire(t *testing.T) {
	t.Parallel()

	clock := &testClock{now: time.Now()}
	_, a, err := buildServer(config{Issuer: "http://127.0.0.1:1", RedirectURI: defaultRedirectURI}, clock.Now)
	require.NoError(t, err)

	browser := &session.Session{ID: "browser"}
	a.begin(browser.ID, "request", clock.Now())

	a.mu.Lock()
	a.update(browser.ID, "request", func(p *pendingRequest) { p.answer = &consentAnswer{subject: "alice", allow: true} })
	a.mu.Unlock()

	_, answered := a.answerOf(browser, "request", "alice")
	require.True(t, answered)

	_, answered = a.answerOf(browser, "request", "bob")
	require.False(t, answered, "alice's answer, not bob's")
	require.False(t, a.startedAt(browser, "request").IsZero())

	clock.Advance(oidcprovider.MaxInteractionDuration + time.Second)

	_, answered = a.answerOf(browser, "request", "alice")
	assert.False(t, answered, "an answer expires with its request")
	assert.True(t, a.startedAt(browser, "request").IsZero(), "so does a login start")

	// A login start counts for MaxInteractionDuration, however recently its
	// request was used.
	a.begin(browser.ID, "later", clock.Now())
	clock.Advance(oidcprovider.MaxInteractionDuration - time.Minute)

	a.mu.Lock()
	a.update(browser.ID, "later", func(p *pendingRequest) { p.answer = &consentAnswer{subject: "alice", allow: true} })
	a.mu.Unlock()

	clock.Advance(2 * time.Minute)

	_, answered = a.answerOf(browser, "later", "alice")
	assert.True(t, answered, "the request was used a minute ago")
	assert.True(t, a.startedAt(browser, "later").IsZero(), "its login started too long ago")
}

// matchingHasher reports every password as matching.
type matchingHasher struct{ password.Hasher }

func (matchingHasher) Verify(context.Context, string, string) (bool, error) { return true, nil }

// TestUnknownUsernamesNeverSignIn: whatever the dummy comparison answers,
// an unknown username is refused.
func TestUnknownUsernamesNeverSignIn(t *testing.T) {
	t.Parallel()

	_, a, err := buildServer(config{Issuer: "http://127.0.0.1:1", RedirectURI: defaultRedirectURI}, time.Now)
	require.NoError(t, err)

	a.hasher = matchingHasher{a.hasher}
	assert.False(t, a.verifyPassword(t.Context(), "nobody", "anything"))
	assert.True(t, a.verifyPassword(t.Context(), "alice", "anything"))
}

// newClockedHarness is newHarness on the clock of the provider, the
// application and its sessions; setup changes the application before the
// server starts.
func newClockedHarness(t *testing.T, clock *testClock, setup func(*app)) *harness {
	t.Helper()

	srv := httptest.NewUnstartedServer(nil)
	issuer := "http://" + srv.Listener.Addr().String()

	handler, a, err := buildServer(config{Issuer: issuer, RedirectURI: defaultRedirectURI}, clock.Now)
	require.NoError(t, err)

	setup(a)

	srv.Config.Handler = handler
	srv.Start()
	t.Cleanup(srv.Close)

	h := &harness{t: t, issuer: issuer, browser: newBrowser(t)}
	h.getJSON(issuer+"/.well-known/openid-configuration", &h.doc)

	return h
}

// TestConsentAnswerIsTheAnsweringEndUsers: a consent answer belongs to the
// end-user who gave it. alice answers the consent page of a request but her
// browser does not resume it; the request later needs a new login
// (max_age) and bob signs in, in that browser: he is shown the consent
// page — alice's answer is not his — and nothing is remembered for him.
func TestConsentAnswerIsTheAnsweringEndUsers(t *testing.T) {
	t.Parallel()

	clock := &testClock{now: time.Now()}

	var a *app

	h := newClockedHarness(t, clock, func(app *app) {
		a = app

		bobHash, err := app.hasher.Hash(t.Context(), "bob-secret")
		require.NoError(t, err)

		app.accounts["bob"] = account{passwordHash: bobHash, claims: map[string]any{"name": "Bob"}}
	})

	_, challenge := pkce()
	_, page := h.signIn(h.authorizeURL(challenge, "n-0", "scope", "openid"))
	require.NotEmpty(t, redirected(t, h.consent(page, "allow", false)).Get("code"))

	_, challenge = pkce()
	request := h.authorizeURL(challenge, "n-1", "scope", "openid profile email", "max_age", "60")
	resp, page := h.do(h.browser, http.MethodGet, request, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	fields := formFields(t, page)
	fields.Set("decision", "allow")
	resp, _ = h.do(h.browser, http.MethodPost, h.issuer+"/consent", fields)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode, "alice allows; her browser does not resume")

	clock.Advance(2 * time.Minute)

	resp, page = h.do(h.browser, http.MethodGet, request, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, page, `name="username"`, "max_age: the login page")

	login := formFields(t, page)
	login.Set("username", "bob")
	login.Set("password", "bob-secret")
	resp, _ = h.do(h.browser, http.MethodPost, h.issuer+"/login", login)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)

	resp, page = h.do(h.browser, http.MethodGet, h.issuer+resp.Header.Get("Location"), nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "bob's consent page, not a code")
	assert.Contains(t, page, `name="decision"`)

	a.mu.Lock()
	_, remembered := a.consents["bob\x00"+rpClientID]
	a.mu.Unlock()
	assert.False(t, remembered, "no consent remembered for bob")
}

// TestCompletedRequestsAreForgotten: once an authorization request is
// answered, its consent answer is forgotten — replaying the very same
// request shows the consent page again, offline access included (OIDC Core
// §11: consent to offline access is obtained every time).
func TestCompletedRequestsAreForgotten(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	verifier, challenge := pkce()
	request := h.authorizeURL(challenge, "n-1", "scope", "openid profile offline_access", "prompt", "consent")

	_, page := h.signIn(request)
	require.True(t, offersOffline(page))
	require.NotEmpty(t, h.exchange(h.consent(page, "allow", true), verifier).RefreshToken)

	resp, page := h.do(h.browser, http.MethodGet, request, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "the consent page again, not a code")
	assert.True(t, offersOffline(page), "offline access asked for again")
}
