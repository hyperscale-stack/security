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
	"sync"
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
		c := op.client(t, func(cfg *oidcclient.Config) { cfg.InsecureCookies, cfg.RedirectURL = true, testLocalRedirectURL })

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

	// The application's own cookies come first — oldest — and are never
	// touched, __Host- prefixed or not.
	app := []*http.Cookie{{Name: "__Host-session", Value: "app"}, {Name: "session", Value: "app"}}

	var existing []*http.Cookie
	for i := range 6 {
		existing = append(existing, &http.Cookie{Name: "__Host-oidc-" + strings.Repeat(string(rune('a'+i)), 16), Value: "v"})
	}

	rec := startLogin(t, c, append(app, existing...)...)

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

// TestStartLoginLeavesApplicationCookies checks that only binding cookies —
// the prefix followed by 16 lowercase hex digits — are counted and expired
// by the cap: the application's own cookies sharing the prefix are never
// touched, whether the cookies are __Host- or, with InsecureCookies, plain.
func TestStartLoginLeavesApplicationCookies(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		insecure bool
		prefix   string
		app      []string // the application's cookies, oldest first
	}{
		"secure": {prefix: "__Host-oidc-", app: []string{
			"__Host-oidc-session", "__Host-oidc-0123456789ABCDEF", "__Host-oidc-0123456789abcde", "__Host-oidc-0123456789abcdef0",
		}},
		"insecure": {insecure: true, prefix: "oidc-", app: []string{"oidc-session", "oidc-provider", "oidc-0123456789ABCDEF"}},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t)
			c := op.client(t, func(cfg *oidcclient.Config) {
				if tc.insecure {
					cfg.InsecureCookies, cfg.RedirectURL = true, testLocalRedirectURL
				}
			})

			var cookies, bindings []*http.Cookie

			for _, name := range tc.app {
				cookies = append(cookies, &http.Cookie{Name: name, Value: "app"})
			}

			for i := range 4 {
				bindings = append(bindings, &http.Cookie{Name: tc.prefix + strings.Repeat(string(rune('a'+i)), 16), Value: "v"})
			}

			rec := startLogin(t, c, append(cookies, bindings...)...)

			expired := map[string]bool{}

			for _, ck := range rec.Result().Cookies() {
				if ck.MaxAge < 0 {
					expired[ck.Name] = true
				}
			}

			assert.Equal(t, map[string]bool{bindings[0].Name: true}, expired,
				"the oldest binding cookie goes, so that four remain with the new one; the application's stay")
		})
	}
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

// TestHandleCallbackRedirectQuery checks that the request's own query is
// compared with the query of a RedirectURL that has one.
func TestHandleCallbackRedirectQuery(t *testing.T) {
	t.Parallel()

	for tenant, ok := range map[string]bool{"acme": true, "globex": false} {
		t.Run(tenant, func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t)
			c := op.client(t, func(cfg *oidcclient.Config) { cfg.RedirectURL = testRedirectURL + "?tenant=acme" })

			login := startLogin(t, c)
			state := loginState(t, login)
			code := op.authorize(t, login.Header().Get("Location"))
			binding := cookieNamed(t, login, expectedCookieName("__Host-oidc-", state))

			query := url.Values{"tenant": {tenant}, "code": {code}, "state": {state}}.Encode()

			_, err := c.HandleCallback(httptest.NewRecorder(), callbackRequest(http.MethodGet, testRedirectURL+"?"+query, nil, binding))
			if ok {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, oidcclient.ErrInvalidCallback)
			}
		})
	}
}

// TestHandleCallbackBehindProxy checks the reverse-proxy contract: the
// scheme is the RedirectURL's — TLS is often terminated before the
// application — while the host comes from the Host header, which the proxy
// must preserve.
func TestHandleCallbackBehindProxy(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		target string
		err    error
	}{
		"TLS terminated, Host preserved": {"http://rp.example.com" + testCallbackPath, nil},
		"Host rewritten to the upstream": {"http://app.internal:8080" + testCallbackPath, oidcclient.ErrInvalidCallback},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t)
			c := op.client(t)

			login := startLogin(t, c)
			state := loginState(t, login)
			code := op.authorize(t, login.Header().Get("Location"))
			binding := cookieNamed(t, login, expectedCookieName("__Host-oidc-", state))

			req := callbackRequest(http.MethodGet, tc.target+"?"+url.Values{"code": {code}, "state": {state}}.Encode(), nil, binding)
			require.Nil(t, req.TLS)

			_, err := c.HandleCallback(httptest.NewRecorder(), req)
			if tc.err == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tc.err)
			}
		})
	}
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

// TestHandleCallbackParsedForm checks a form_post callback whose body a
// middleware already parsed (r.ParseForm): the parsed form is used.
func TestHandleCallbackParsedForm(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	c := op.client(t, func(cfg *oidcclient.Config) { cfg.ResponseMode = oidcclient.ResponseModeFormPost })

	login := startLogin(t, c)
	state := loginState(t, login)
	code := op.authorize(t, login.Header().Get("Location"))
	binding := cookieNamed(t, login, expectedCookieName("__Host-oidc-", state))

	req := callbackRequest(http.MethodPost, testRedirectURL, strings.NewReader(url.Values{"code": {code}, "state": {state}}.Encode()), binding)
	require.NoError(t, req.ParseForm())

	id, err := c.HandleCallback(httptest.NewRecorder(), req)
	require.NoError(t, err)
	assert.Equal(t, testSubject, id.Subject)
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
		{"another host", oidcclient.ResponseModeQuery, func(s, c string, b *http.Cookie) *http.Request {
			return callbackRequest(http.MethodGet, "https://tenant.rp.example.com"+testCallbackPath+"?"+form(s, c), nil, b)
		}, oidcclient.ErrInvalidCallback},
		{"another port", oidcclient.ResponseModeQuery, func(s, c string, b *http.Cookie) *http.Request {
			return callbackRequest(http.MethodGet, "https://rp.example.com:8443"+testCallbackPath+"?"+form(s, c), nil, b)
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

	return serveRP(t, op, httptest.NewTLSServer, func(cfg *oidcclient.Config) { cfg.ResponseMode = mode })
}

// serveRP serves StartLogin and HandleCallback for a Client of op on the
// server serve starts, its RedirectURL on that server, modified by the
// mutators.
func serveRP(t *testing.T, op *fakeOP, serve func(http.Handler) *httptest.Server,
	mutators ...func(*oidcclient.Config),
) (*httptest.Server, *http.Client) {
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

	rp := serve(mux)
	t.Cleanup(rp.Close)

	c = op.client(t, append([]func(*oidcclient.Config){func(cfg *oidcclient.Config) {
		cfg.RedirectURL = rp.URL + testCallbackPath
	}}, mutators...)...)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	browser := *op.srv.Client() // a copy: trusts the httptest certificate shared by the RP and the OP
	browser.Jar = jar

	return rp, &browser
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

// TestLeakedStateBurnsThePendingLoginThroughTheVictimBrowser characterizes
// a residual risk, and documents it: an authorization response is not
// authenticated, so whoever learned the state of a pending login can send
// the victim's own browser — which presents the binding cookie, SameSite=Lax
// on a top-level navigation — to the callback with that state. The response
// to that request expires the binding cookie, and with an error (or a
// bogus code) the transaction is consumed: the genuine callback then fails
// (ErrBindingMismatch, the cookie gone) and the user starts over. A
// request carrying the state alone — no code, no error — burns the login
// through the cookie only. Keep the state out of logs (AuthRequest prints
// without it).
func TestLeakedStateBurnsThePendingLoginThroughTheVictimBrowser(t *testing.T) {
	t.Parallel()

	for name, forged := range map[string]url.Values{
		"forged error response": {"error": {"access_denied"}},
		"state alone":           {},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t)

			var (
				mu      sync.Mutex
				lastErr error
			)

			var c *oidcclient.Client

			mux := http.NewServeMux()
			mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
				assert.NoError(t, c.StartLogin(w, r, oidcclient.AuthOptions{}))
			})
			mux.HandleFunc(testCallbackPath, func(w http.ResponseWriter, r *http.Request) {
				_, err := c.HandleCallback(w, r)

				mu.Lock()
				lastErr = err
				mu.Unlock()
			})

			rp := httptest.NewTLSServer(mux)
			t.Cleanup(rp.Close)

			c = op.client(t, func(cfg *oidcclient.Config) { cfg.RedirectURL = rp.URL + testCallbackPath })
			rpURL, err := url.Parse(rp.URL)
			require.NoError(t, err)

			jar, err := cookiejar.New(nil)
			require.NoError(t, err)

			victim := *op.srv.Client()
			victim.Jar = jar
			victim.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

			get := func(target string) error {
				resp, err := victim.Get(target)
				require.NoError(t, err)
				_ = resp.Body.Close()

				mu.Lock()
				defer mu.Unlock()

				return lastErr
			}

			resp, err := victim.Get(rp.URL + "/login")
			require.NoError(t, err)
			_ = resp.Body.Close()

			authURL := resp.Header.Get("Location")
			loc, err := url.Parse(authURL)
			require.NoError(t, err)

			state := loc.Query().Get("state")
			require.Len(t, jar.Cookies(rpURL), 1, "the binding cookie of the pending login")
			binding := jar.Cookies(rpURL)[0].Value
			code := op.authorize(t, authURL)

			// The attacker, knowing the state, makes the victim's browser
			// request the callback.
			forged.Set("state", state)
			require.Error(t, get(rp.URL+testCallbackPath+"?"+forged.Encode()))
			assert.Empty(t, jar.Cookies(rpURL), "the response expired the binding cookie")

			// The genuine response arrives without the cookie.
			err = get(rp.URL + testCallbackPath + "?" + url.Values{"state": {state}, "code": {code}}.Encode())
			require.ErrorIs(t, err, oidcclient.ErrBindingMismatch)
			assert.Zero(t, op.hitCount("/token"))

			// The store: an error response consumed the transaction; the
			// state alone, refused before the store, left it.
			received := receivedOn(rp.URL + testCallbackPath)
			received.RawQuery = url.Values{"state": {state}, "code": {code}}.Encode()
			_, err = c.Complete(context.Background(), oidcclient.Callback{
				Mode: oidcclient.ResponseModeQuery, URL: received, Params: received.Query(), Binding: oidcclient.NewSecret(binding),
			})

			if forged.Has("error") {
				require.ErrorIs(t, err, oidcclient.ErrTransactionNotFound)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestEndToEndInsecureCookiesOnLoopback runs a login over plain http on the
// loopback interface — the local development setup InsecureCookies is for —
// through a browser's cookie jar, which keeps a cookie without Secure on
// http.
func TestEndToEndInsecureCookiesOnLoopback(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	rp, browser := serveRP(t, op, httptest.NewServer, func(cfg *oidcclient.Config) { cfg.InsecureCookies = true })
	require.True(t, strings.HasPrefix(rp.URL, "http://127.0.0.1:"))

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
	id, err := c.HandleCallback(httptest.NewRecorder(), req.WithContext(ctx))
	require.ErrorIs(t, err, context.Canceled, "the request context reaches the token request")
	require.ErrorIs(t, err, oidcclient.ErrTokenEndpoint)
	assert.Nil(t, id)
	op.set(func(op *fakeOP) { assert.Empty(t, op.tokenRequests, "the cancelled request is never sent") })
}
