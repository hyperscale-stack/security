// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startLogin runs StartLogin on a recorder.
func startLogin(t *testing.T, c *oidcclient.Client, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "https://rp.example.com/login", nil)
	for _, ck := range cookies {
		req.AddCookie(ck)
	}

	rec := httptest.NewRecorder()
	require.NoError(t, c.StartLogin(rec, req, oidcclient.AuthOptions{}))

	return rec
}

// loginState returns the state of the authorization request a StartLogin
// response redirects to.
func loginState(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()

	u, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)

	return u.Query().Get("state")
}

func expectedCookieName(prefix, state string) string {
	sum := sha256.Sum256([]byte(state))

	return prefix + hex.EncodeToString(sum[:])[:16]
}

func cookieNamed(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()

	for _, ck := range rec.Result().Cookies() {
		if ck.Name == name {
			return ck
		}
	}

	t.Fatalf("no cookie %s in %v", name, rec.Header().Values("Set-Cookie"))

	return nil
}

// TestStartLoginCookie checks the binding cookie (rfc6265bis-22): __Host-
// prefix (Secure, Path=/, no Domain), HttpOnly, the transaction lifetime,
// SameSite=Lax for a top-level GET callback (§5.6.7.1) and None for the
// cross-site POST of form_post (§8.8.3), and a 303 to the provider.
func TestStartLoginCookie(t *testing.T) {
	t.Parallel()

	cases := []struct {
		mode     oidcclient.ResponseMode
		sameSite http.SameSite
		raw      string
	}{
		{oidcclient.ResponseModeQuery, http.SameSiteLaxMode, "SameSite=Lax"},
		{oidcclient.ResponseModeFormPost, http.SameSiteNoneMode, "SameSite=None"},
	}

	for _, tc := range cases {
		t.Run(string(tc.mode), func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t)
			c := op.client(t, func(cfg *oidcclient.Config) { cfg.ResponseMode = tc.mode })

			rec := startLogin(t, c)
			assert.Equal(t, http.StatusSeeOther, rec.Code)
			assert.True(t, strings.HasPrefix(rec.Header().Get("Location"), op.srv.URL+"/authorize?"))
			assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
			assert.Equal(t, "no-referrer", rec.Header().Get("Referrer-Policy"))

			state := loginState(t, rec)
			ck := cookieNamed(t, rec, expectedCookieName("__Host-oidc-", state))
			assert.Regexp(t, b64url43, ck.Value)
			assert.Equal(t, "/", ck.Path)
			assert.Empty(t, ck.Domain)
			assert.True(t, ck.Secure)
			assert.True(t, ck.HttpOnly)
			assert.Equal(t, tc.sameSite, ck.SameSite)
			assert.Equal(t, 600, ck.MaxAge)
			assert.Contains(t, rec.Header().Get("Set-Cookie"), tc.raw)
		})
	}

	t.Run("insecure cookies for local development", func(t *testing.T) {
		t.Parallel()

		op := newFakeOP(t)
		c := op.client(t, func(cfg *oidcclient.Config) { cfg.InsecureCookies = true })

		rec := startLogin(t, c)
		ck := cookieNamed(t, rec, expectedCookieName("oidc-", loginState(t, rec)))
		assert.False(t, ck.Secure)
		assert.True(t, ck.HttpOnly)
	})

	t.Run("refused options write nothing", func(t *testing.T) {
		t.Parallel()

		op := newFakeOP(t)
		c := op.client(t)

		rec := httptest.NewRecorder()
		err := c.StartLogin(rec, httptest.NewRequest(http.MethodGet, "https://rp.example.com/login", nil),
			oidcclient.AuthOptions{Prompt: []string{"none", "login"}})
		require.ErrorIs(t, err, oidcclient.ErrInvalidAuthRequest)
		assert.Empty(t, rec.Header().Values("Set-Cookie"))
		assert.Empty(t, rec.Header().Get("Location"))
	})
}

// TestStartLoginCapsCookies checks that a page triggering many login
// starts cannot grow the Cookie header without bound: beyond four pending
// logins the oldest binding cookies are expired.
func TestStartLoginCapsCookies(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	c := op.client(t)

	var existing []*http.Cookie
	for i := range 6 {
		existing = append(existing, &http.Cookie{Name: "__Host-oidc-" + strings.Repeat(string(rune('a'+i)), 16), Value: "v"})
	}

	existing = append(existing, &http.Cookie{Name: "session", Value: "app"})

	rec := startLogin(t, c, existing...)

	expired := map[string]bool{}

	for _, ck := range rec.Result().Cookies() {
		if ck.MaxAge < 0 {
			expired[ck.Name] = true
			assert.True(t, ck.Secure)
			assert.Equal(t, "/", ck.Path)
		}
	}

	assert.Equal(t, map[string]bool{existing[0].Name: true, existing[1].Name: true, existing[2].Name: true}, expired,
		"the three oldest of six go, leaving three plus the new one")
}

// callbackRequest is the request a user agent sends to the callback.
func callbackRequest(method, target string, body io.Reader, cookies ...*http.Cookie) *http.Request {
	req := httptest.NewRequest(method, target, body)
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	for _, ck := range cookies {
		req.AddCookie(ck)
	}

	return req
}

func TestHandleCallbackQuery(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	c := op.client(t)

	login := startLogin(t, c)
	state := loginState(t, login)
	code := op.authorize(t, login.Header().Get("Location"))
	binding := cookieNamed(t, login, expectedCookieName("__Host-oidc-", state))

	rec := httptest.NewRecorder()
	id, err := c.HandleCallback(rec, callbackRequest(http.MethodGet,
		testRedirectURL+"?"+url.Values{"code": {code}, "state": {state}}.Encode(), nil, binding))
	require.NoError(t, err)
	assert.Equal(t, testSubject, id.Subject)

	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.Equal(t, "no-referrer", rec.Header().Get("Referrer-Policy"))

	cleared := cookieNamed(t, rec, binding.Name)
	assert.Negative(t, cleared.MaxAge)
	assert.True(t, cleared.Secure)
	assert.Empty(t, cleared.Value)
}

func TestHandleCallbackFormPost(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	c := op.client(t, func(cfg *oidcclient.Config) { cfg.ResponseMode = oidcclient.ResponseModeFormPost })

	login := startLogin(t, c)
	state := loginState(t, login)
	code := op.authorize(t, login.Header().Get("Location"))
	binding := cookieNamed(t, login, expectedCookieName("__Host-oidc-", state))
	form := url.Values{"code": {code}, "state": {state}}.Encode()

	rec := httptest.NewRecorder()
	id, err := c.HandleCallback(rec, callbackRequest(http.MethodPost, testRedirectURL, strings.NewReader(form), binding))
	require.NoError(t, err)
	assert.Equal(t, testSubject, id.Subject)

	cleared := cookieNamed(t, rec, binding.Name)
	assert.Negative(t, cleared.MaxAge)
	assert.Equal(t, http.SameSiteNoneMode, cleared.SameSite)
}

// TestHandleCallbackRefuses checks the request shape per response mode;
// nothing reaches the token endpoint.
func TestHandleCallbackRefuses(t *testing.T) {
	t.Parallel()

	type request func(state, code string, binding *http.Cookie) *http.Request

	form := func(state, code string) string { return url.Values{"code": {code}, "state": {state}}.Encode() }

	cases := []struct {
		name string
		mode oidcclient.ResponseMode
		req  request
		err  error
	}{
		{"POST to a query callback", oidcclient.ResponseModeQuery, func(s, c string, b *http.Cookie) *http.Request {
			return callbackRequest(http.MethodPost, testRedirectURL+"?"+form(s, c), nil, b)
		}, oidcclient.ErrInvalidCallback},
		{"POST of a form to a query callback", oidcclient.ResponseModeQuery, func(s, c string, b *http.Cookie) *http.Request {
			return callbackRequest(http.MethodPost, testRedirectURL, strings.NewReader(form(s, c)), b)
		}, oidcclient.ErrInvalidCallback},
		{"GET to a form_post callback", oidcclient.ResponseModeFormPost, func(s, c string, b *http.Cookie) *http.Request {
			return callbackRequest(http.MethodGet, testRedirectURL+"?"+form(s, c), nil, b)
		}, oidcclient.ErrInvalidCallback},
		{"GET with a form body to a form_post callback", oidcclient.ResponseModeFormPost, func(s, c string, b *http.Cookie) *http.Request {
			return callbackRequest(http.MethodGet, testRedirectURL, strings.NewReader(form(s, c)), b)
		}, oidcclient.ErrInvalidCallback},
		{"form_post with a text/plain body", oidcclient.ResponseModeFormPost, func(s, c string, b *http.Cookie) *http.Request {
			r := callbackRequest(http.MethodPost, testRedirectURL, strings.NewReader(form(s, c)), b)
			r.Header.Set("Content-Type", "text/plain")

			return r
		}, oidcclient.ErrInvalidCallback},
		{"form_post with a JSON body", oidcclient.ResponseModeFormPost, func(s, c string, b *http.Cookie) *http.Request {
			r := callbackRequest(http.MethodPost, testRedirectURL, strings.NewReader(`{"code":"x"}`), b)
			r.Header.Set("Content-Type", "application/json")

			return r
		}, oidcclient.ErrInvalidCallback},
		{"form_post body too large", oidcclient.ResponseModeFormPost, func(s, c string, b *http.Cookie) *http.Request {
			return callbackRequest(http.MethodPost, testRedirectURL, strings.NewReader(form(s, c)+"&pad="+strings.Repeat("p", 64<<10)), b)
		}, oidcclient.ErrInvalidCallback},
		{"form_post with response parameters in the query", oidcclient.ResponseModeFormPost, func(s, c string, b *http.Cookie) *http.Request {
			return callbackRequest(http.MethodPost, testRedirectURL+"?code=injected", strings.NewReader(form(s, c)), b)
		}, oidcclient.ErrInvalidCallback},
		{"form_post with a malformed body", oidcclient.ResponseModeFormPost, func(s, c string, b *http.Cookie) *http.Request {
			return callbackRequest(http.MethodPost, testRedirectURL, strings.NewReader(form(s, c)+"&x=%zz"), b)
		}, oidcclient.ErrInvalidCallback},
		{"form_post with a malformed query", oidcclient.ResponseModeFormPost, func(s, c string, b *http.Cookie) *http.Request {
			return callbackRequest(http.MethodPost, testRedirectURL+"?x=%zz", strings.NewReader(form(s, c)), b)
		}, oidcclient.ErrInvalidCallback},
		{"query with a malformed query", oidcclient.ResponseModeQuery, func(s, c string, b *http.Cookie) *http.Request {
			return callbackRequest(http.MethodGet, testRedirectURL+"?"+form(s, c)+"&x=%zz", nil, b)
		}, oidcclient.ErrInvalidCallback},
		{"another path", oidcclient.ResponseModeQuery, func(s, c string, b *http.Cookie) *http.Request {
			return callbackRequest(http.MethodGet, "https://rp.example.com/oidc/other/callback?"+form(s, c), nil, b)
		}, oidcclient.ErrInvalidCallback},
		{"no binding cookie", oidcclient.ResponseModeQuery, func(s, c string, _ *http.Cookie) *http.Request {
			return callbackRequest(http.MethodGet, testRedirectURL+"?"+form(s, c), nil)
		}, oidcclient.ErrBindingMismatch},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t)
			c := op.client(t, func(cfg *oidcclient.Config) { cfg.ResponseMode = tc.mode })

			login := startLogin(t, c)
			state := loginState(t, login)
			code := op.authorize(t, login.Header().Get("Location"))
			binding := cookieNamed(t, login, expectedCookieName("__Host-oidc-", state))

			id, err := c.HandleCallback(httptest.NewRecorder(), tc.req(state, code, binding))
			require.ErrorIs(t, err, tc.err)
			assert.Nil(t, id)
			assert.Zero(t, op.hitCount("/token"))
		})
	}
}

// newRP serves StartLogin and HandleCallback for c on an httptest TLS
// server, as an application would.
func newRP(t *testing.T, op *fakeOP, mode oidcclient.ResponseMode) (*httptest.Server, *http.Client) {
	t.Helper()

	var c *oidcclient.Client

	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		if err := c.StartLogin(w, r, oidcclient.AuthOptions{}); err != nil {
			http.Error(w, "login failed", http.StatusInternalServerError)
		}
	})
	mux.HandleFunc(testCallbackPath, func(w http.ResponseWriter, r *http.Request) {
		id, err := c.HandleCallback(w, r)
		if err != nil {
			http.Error(w, "callback failed: "+err.Error(), http.StatusUnauthorized)

			return
		}

		_, _ = io.WriteString(w, "hello "+id.Subject)
	})

	rp := httptest.NewTLSServer(mux)
	t.Cleanup(rp.Close)

	c = op.client(t, func(cfg *oidcclient.Config) {
		cfg.RedirectURL = rp.URL + testCallbackPath
		cfg.ResponseMode = mode
	})

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	browser := rp.Client() // trusts the httptest certificate shared by the RP and the OP
	browser.Jar = jar

	return rp, browser
}

func TestEndToEndQuery(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	rp, browser := newRP(t, op, oidcclient.ResponseModeQuery)

	resp, err := browser.Get(rp.URL + "/login")
	require.NoError(t, err)

	body := readAll(t, resp.Body)
	assert.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	assert.Equal(t, "hello "+testSubject, string(body))
}

func TestEndToEndFormPost(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	rp, browser := newRP(t, op, oidcclient.ResponseModeFormPost)

	resp, err := browser.Get(rp.URL + "/login") // follows to the OP's auto-submitted form
	require.NoError(t, err)
	_ = readAll(t, resp.Body)

	var code, state string

	op.set(func(op *fakeOP) {
		require.Len(t, op.grants, 1)

		for k, g := range op.grants {
			code, state = k, g.state
			assert.Equal(t, "form_post", g.responseMode)
		}
	})

	resp, err = browser.PostForm(rp.URL+testCallbackPath, url.Values{"code": {code}, "state": {state}})
	require.NoError(t, err)

	body := readAll(t, resp.Body)
	assert.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	assert.Equal(t, "hello "+testSubject, string(body))
}

// TestParallelLogins checks that two logins started in one browser — two
// tabs — both complete: each has its own binding cookie.
func TestParallelLogins(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	c := op.client(t)

	first, second := startLogin(t, c), startLogin(t, c)

	for _, login := range []*httptest.ResponseRecorder{second, first} {
		state := loginState(t, login)
		code := op.authorize(t, login.Header().Get("Location"))

		var cookies []*http.Cookie
		for _, l := range []*httptest.ResponseRecorder{first, second} {
			cookies = append(cookies, l.Result().Cookies()...)
		}

		_, err := c.HandleCallback(httptest.NewRecorder(), callbackRequest(http.MethodGet,
			testRedirectURL+"?"+url.Values{"code": {code}, "state": {state}}.Encode(), nil, cookies...))
		require.NoError(t, err)
	}
}

func TestHandleCallbackContext(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	c := op.client(t)
	login := startLogin(t, c)
	state := loginState(t, login)
	code := op.authorize(t, login.Header().Get("Location"))
	binding := cookieNamed(t, login, expectedCookieName("__Host-oidc-", state))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	req := callbackRequest(http.MethodGet, testRedirectURL+"?"+url.Values{"code": {code}, "state": {state}}.Encode(), nil, binding)
	_, err := c.HandleCallback(httptest.NewRecorder(), req.WithContext(ctx))
	require.Error(t, err, "the request context reaches the token request")
}
