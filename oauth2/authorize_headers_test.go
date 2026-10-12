// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requireProtectiveHeaders asserts the headers every /authorize response
// carries: not framed (RFC 6749 §10.13, RFC 9700 §4.16), not cached, and no
// Referer to another origin (RFC 9700 §4.2.4) — same-origin, so that the
// consent POST keeps its Origin header.
func requireProtectiveHeaders(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()

	h := rec.Header()
	assert.Equal(t, "DENY", h.Get("X-Frame-Options"))
	assert.Contains(t, h.Values("Content-Security-Policy"), "frame-ancestors 'none'")
	assert.Equal(t, "no-store", h.Get("Cache-Control"))
	assert.Equal(t, "same-origin", h.Get("Referrer-Policy"))
}

// renderPage is a ConsentFunc rendering its login page.
func renderPage(w http.ResponseWriter, _ *http.Request, _ *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprint(w, "<form method=post><button>Approve</button></form>")

	return nil, nil
}

// TestAuthorizeResponsesCarryProtectiveHeaders: every /authorize response —
// the page a ConsentFunc renders, a redirect carrying a code or an error,
// a bare error — carries the protective headers, set before anything else
// runs.
func TestAuthorizeResponsesCarryProtectiveHeaders(t *testing.T) {
	t.Parallel()

	get := func(q url.Values) *http.Request {
		return httptest.NewRequest(http.MethodGet, authorizePath+"?"+q.Encode(), nil)
	}
	post := func(q url.Values) *http.Request {
		return boundsPost(authorizePath, strings.NewReader(q.Encode()))
	}
	with := func(key, value string) url.Values {
		q := boundsQuery()
		q.Set(key, value)

		return q
	}

	cases := []struct {
		name    string
		req     *http.Request
		consent oauth2.ConsentFunc
		status  int
	}{
		{"the ConsentFunc's page", get(boundsQuery()), renderPage, http.StatusOK},
		{"a code (GET)", get(boundsQuery()), approve, http.StatusFound},
		{"a code (POST)", post(boundsQuery()), approve, http.StatusSeeOther},
		{"an implicit token", get(with("response_type", "token")), approve, http.StatusFound},
		{"a redirected error", get(with("scope", "admin")), approve, http.StatusFound},
		{"an unknown client", get(with("client_id", "ghost")), approve, http.StatusBadRequest},
		{"an unregistered redirect URI", get(with("redirect_uri", "https://evil.example/cb")), approve, http.StatusBadRequest},
		{"a request too large", get(with("pad", strings.Repeat("x", oauth2.DefaultMaxRequestBytes))), approve, http.StatusBadRequest},
		{"another method", httptest.NewRequest(http.MethodPut, authorizePath, nil), approve, http.StatusMethodNotAllowed},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := newBoundsEnv(t, 0, nil, nil)
			rec := serve(env.authorizeHandler(tc.consent), tc.req)

			require.Equal(t, tc.status, rec.Code, rec.Body.String())
			requireProtectiveHeaders(t, rec)
		})
	}
}

// TestAuthorizeAnswersAnotherMethodWithAllow: a 405 lists the methods the
// endpoint serves (RFC 9110 §15.5.6).
func TestAuthorizeAnswersAnotherMethodWithAllow(t *testing.T) {
	t.Parallel()

	env := newBoundsEnv(t, 0, nil, nil)
	rec := serve(env.authorizeHandler(approve), httptest.NewRequest(http.MethodDelete, authorizePath, nil))

	require.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	assert.Equal(t, "GET, POST", rec.Header().Get("Allow"))
}

// TestConsentFuncCanReplaceProtectiveHeaders: the ConsentFunc, which
// renders the page, may allow framing by origins it trusts (RFC 9700 §4.16
// lets administrators configure them per client).
func TestConsentFuncCanReplaceProtectiveHeaders(t *testing.T) {
	t.Parallel()

	env := newBoundsEnv(t, 0, nil, nil)
	partner := func(w http.ResponseWriter, r *http.Request, ar *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
		w.Header().Del("X-Frame-Options")
		w.Header().Set("Content-Security-Policy", "frame-ancestors https://partner.example")

		return renderPage(w, r, ar)
	}

	rec := serve(env.authorizeHandler(partner), httptest.NewRequest(http.MethodGet, authorizePath+"?"+boundsQuery().Encode(), nil))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, rec.Header().Get("X-Frame-Options"))
	assert.Equal(t, []string{"frame-ancestors https://partner.example"}, rec.Header().Values("Content-Security-Policy"))
}

// TestAuthorizeKeepsAnApplicationCSP: a Content-Security-Policy a middleware
// set is kept — the handler adds its frame-ancestors policy, and browsers
// enforce both.
func TestAuthorizeKeepsAnApplicationCSP(t *testing.T) {
	t.Parallel()

	env := newBoundsEnv(t, 0, nil, nil)
	h := env.authorizeHandler(renderPage)
	csp := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		h.ServeHTTP(w, r)
	})

	rec := serve(csp, httptest.NewRequest(http.MethodGet, authorizePath+"?"+boundsQuery().Encode(), nil))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, []string{"default-src 'self'", "frame-ancestors 'none'"}, rec.Header().Values("Content-Security-Policy"))
}

// TestAuthorizePostRedirectsWithSeeOther pins RFC 9700 §4.12: a redirect
// answering a POST — which may carry the resource owner's credentials — is
// a 303, which every user agent follows with a GET; a GET keeps the 302 of
// RFC 6749 §4.1.2.
func TestAuthorizePostRedirectsWithSeeOther(t *testing.T) {
	t.Parallel()

	with := func(key, value string) url.Values {
		q := boundsQuery()
		q.Set(key, value)

		return q
	}
	deny := consentWith(&oauth2.Consent{Approved: false}, nil)

	cases := []struct {
		name    string
		q       url.Values
		consent oauth2.ConsentFunc
	}{
		{"an approval", boundsQuery(), approve},
		{"a refusal", boundsQuery(), deny},
		{"an error before the ConsentFunc", with("scope", "admin"), approve},
		{"an implicit token", with("response_type", "token"), approve},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := newBoundsEnv(t, 0, nil, nil)
			h := env.authorizeHandler(tc.consent)

			rec := serve(h, boundsPost(authorizePath, strings.NewReader(tc.q.Encode())))
			assert.Equal(t, http.StatusSeeOther, rec.Code, "POST")
			assert.NotEmpty(t, rec.Header().Get("Location"))

			rec = serve(h, httptest.NewRequest(http.MethodGet, authorizePath+"?"+tc.q.Encode(), nil))
			assert.Equal(t, http.StatusFound, rec.Code, "GET")
		})
	}
}
