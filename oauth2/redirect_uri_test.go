// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateRedirectURI pins the registration rules: an absolute URI (RFC
// 6749 §3.1.2) of RFC 3986 characters, without fragment; a host and no
// userinfo for http(s); a private-use scheme holding a "." for native apps
// (RFC 8252 §7.1, §8.4) — which refuses javascript:, data:, file: and the
// like; and a query naming none of the authorization response parameters,
// which RFC 6749 §3.1 forbids twice (§3.1.2 keeps the registered query).
func TestValidateRedirectURI(t *testing.T) {
	t.Parallel()

	valid := []string{
		"https://app.example/cb",
		"https://app.example/cb?b=2&a=1",
		"https://app.example/cb?a=1;b=2",
		"https://app.example/cb?flag",
		"https://app.example/cb?sig=abc%2Fdef%3D",
		"https://app.example/cb?State=x",
		"https://app.example/cb?",
		"https://app.example:8443/cb",
		"http://localhost:1337/callback",
		"http://127.0.0.1:51004/cb",
		"http://[::1]/cb",
		"com.example.app:/oauth2redirect/example-provider",
		"com.example.app:cb",
		"HTTPS://App.Example/CB",
	}

	for _, uri := range valid {
		assert.NoError(t, oauth2.ValidateRedirectURI(uri), uri)
	}

	const (
		empty    = "empty"
		fragment = "fragment"
		chars    = "outside RFC 3986"
		escape   = "percent-encoding"
		relative = "not an absolute URI"
		period   = "without a period"
		host     = "no host"
		userinfo = "userinfo"
		query    = "authorization response parameter"
	)

	invalid := []struct{ uri, reason string }{
		{"", empty},
		{"/relative/cb", relative},
		{"cb", relative},
		{"//app.example/cb", relative},
		{"https://app.example/cb#frag", fragment},
		{"https://app.example/cb#", fragment},
		{"javascript:alert(1)", period},
		{"JavaScript:alert(1)", period},
		{"data:text/html,x", period},
		{"vbscript:x", period},
		{"file:///etc/passwd", period},
		{"myapp://cb", period},
		{"urn:ietf:wg:oauth:2.0:oob", period},
		{"http:/cb", host},
		{"https://", host},
		{"https://user@app.example/cb", userinfo},
		{"https://user:pass@app.example/cb", userinfo},
		{"https://app.example/a b", chars},
		{"https://app.example/a\tb", chars},
		{"https://app.example/é", chars},
		{"https://app.example/a<b", chars},
		{"https://app.example/c%zz", escape},
		{"https://app.example/c%2", escape},
		{"https://app.example/cb?x=%zz", escape},
		{"https://app.example/cb?code=static", query},
		{"https://app.example/cb?state=fixed", query},
		{"https://app.example/cb?iss=x", query},
		{"https://app.example/cb?error=x", query},
		{"https://app.example/cb?error_description=", query},
		{"https://app.example/cb?error_uri=x", query},
		{"https://app.example/cb?a=1&state=x", query},
		{"https://app.example/cb?a=1;state=x", query},
		{"https://app.example/cb?a=1;code=y", query},
		{"https://app.example/cb?%73tate=x", query},
		{"https://app.example/cb?state", query},
		{"https://app.example:port/cb", "invalid port"},
		{"https://[::1/cb", "missing ']'"},
	}

	for _, tc := range invalid {
		err := oauth2.ValidateRedirectURI(tc.uri)
		assert.ErrorIs(t, err, oauth2.ErrInvalidRedirectURI, tc.uri)
		assert.ErrorContains(t, err, tc.reason, tc.uri)
	}
}

// redirectEnv is a boundsEnv whose client "machine" registers uris.
func redirectEnv(t *testing.T, uris ...string) *boundsEnv {
	t.Helper()

	env := newBoundsEnv(t, 0, nil, nil)
	client := confidentialClient([]string{oauth2.GrantTypeAuthorizationCode, oauth2.GrantTypeImplicit}, []string{"read"})
	client.RedirectURIValues = uris
	env.clients.clients["machine"] = client

	return env
}

// authorizeTo runs a GET /authorize of "machine" on env with redirect_uri
// (omitted when empty) and the response type, approved.
func authorizeTo(env *boundsEnv, redirectURI, responseType string) *httptest.ResponseRecorder {
	q := boundsQuery()
	q.Set("response_type", responseType)
	q.Del("redirect_uri")

	if redirectURI != "" {
		q.Set("redirect_uri", redirectURI)
	}

	return serve(env.authorizeHandler(approve), httptest.NewRequest(http.MethodGet, authorizePath+"?"+q.Encode(), nil))
}

// TestAuthorizeRefusesAnInvalidRegisteredRedirectURI: a registered redirect
// URI the rules refuse is an invalid redirection URI, never redirected to
// (RFC 6749 §3.1.2.4) — whether the request names it or omits it as the
// client's sole one; the cause reaches the hook.
func TestAuthorizeRefusesAnInvalidRegisteredRedirectURI(t *testing.T) {
	t.Parallel()

	for _, uri := range []string{
		"https://app.example/cb#section", "/relative/cb", "javascript:alert(1)", "myapp://cb",
		"https://app.example/cb?state=fixed&code=static",
	} {
		for _, named := range []bool{true, false} {
			t.Run(uri, func(t *testing.T) {
				t.Parallel()

				env := redirectEnv(t, uri)

				requested := ""
				if named {
					requested = uri
				}

				rec := authorizeTo(env, requested, "code")
				assert.Equal(t, http.StatusBadRequest, rec.Code)
				assert.Equal(t, "oauth2: invalid redirect_uri\n", rec.Body.String())
				assert.Empty(t, rec.Header().Get("Location"), "never redirected")
				assert.Zero(t, env.store.writes.Load())
				assert.True(t, env.sink.matches(oauth2.ErrInvalidRedirectURI), "the cause reaches the hook")
			})
		}
	}
}

// TestAuthorizeKeepsTheRegisteredQuery pins RFC 6749 §3.1.2: the query of
// the registered redirect URI "MUST be retained when adding additional query
// parameters" — byte for byte, in its order, whatever its separators.
func TestAuthorizeKeepsTheRegisteredQuery(t *testing.T) {
	t.Parallel()

	cases := []struct {
		registered, prefix string
	}{
		{"https://app.example/cb?b=2&a=1", "https://app.example/cb?b=2&a=1&"},
		{"https://app.example/cb?a=1;b=2", "https://app.example/cb?a=1;b=2&"},
		{"https://app.example/cb?flag", "https://app.example/cb?flag&"},
		{"https://app.example/cb?sig=abc%2Fdef%3D", "https://app.example/cb?sig=abc%2Fdef%3D&"},
		{"https://app.example/cb?", "https://app.example/cb?code="},
		{"https://app.example/cb?a=1&", "https://app.example/cb?a=1&code="},
		{"https://app.example/cb", "https://app.example/cb?code="},
		{"com.example.app:/oauth2redirect", "com.example.app:/oauth2redirect?code="},
	}

	for _, tc := range cases {
		t.Run(tc.registered, func(t *testing.T) {
			t.Parallel()

			env := redirectEnv(t, tc.registered)

			rec := authorizeTo(env, tc.registered, "code")
			require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())

			loc := rec.Header().Get("Location")
			assert.True(t, strings.HasPrefix(loc, tc.prefix), "%s keeps %s", loc, tc.prefix)
			assert.NotContains(t, loc, "&&")

			// An error redirect keeps it too.
			q := boundsQuery()
			q.Set("redirect_uri", tc.registered)
			q.Set("scope", "admin")
			rec = serve(env.authorizeHandler(approve), httptest.NewRequest(http.MethodGet, authorizePath+"?"+q.Encode(), nil))
			require.Equal(t, http.StatusFound, rec.Code)
			assert.True(t, strings.HasPrefix(rec.Header().Get("Location"), strings.TrimSuffix(tc.prefix, "code=")))
			assert.Contains(t, rec.Header().Get("Location"), "error=invalid_scope")
		})
	}
}

// TestImplicitRedirectKeepsTheQueryAndAppendsTheFragment: the implicit flow
// answers in the fragment (RFC 6749 §4.2.2) of a URI that has none — the
// registered query is kept.
func TestImplicitRedirectKeepsTheQueryAndAppendsTheFragment(t *testing.T) {
	t.Parallel()

	env := redirectEnv(t, "https://app.example/cb?x=1")

	rec := authorizeTo(env, "https://app.example/cb?x=1", "token")
	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())

	loc := rec.Header().Get("Location")
	assert.True(t, strings.HasPrefix(loc, "https://app.example/cb?x=1#access_token="), loc)
	assert.Equal(t, 1, strings.Count(loc, "#"))
}

// TestLoopbackRedirectURIAcceptsAnyPort pins RFC 8252 §7.3 ("The
// authorization server MUST allow any port to be specified at the time of
// the request for loopback IP redirect URIs") and RFC 9700 §2.1: a request
// may change the port of a registered http://127.0.0.1 or http://[::1]
// redirect URI, and nothing else — the code is bound to the URI requested,
// which the token request must present.
func TestLoopbackRedirectURIAcceptsAnyPort(t *testing.T) {
	t.Parallel()

	registered := []string{"http://127.0.0.1/callback", "http://[::1]/callback", "http://127.0.0.1:8080/cb"}

	accepted := []string{
		"http://127.0.0.1:1/callback",
		"http://127.0.0.1:51004/callback",
		"http://127.0.0.1:65535/callback",
		"http://[::1]:61023/callback",
		"http://127.0.0.1:9999/cb",
		"http://127.0.0.1/cb",
	}

	for _, requested := range accepted {
		t.Run(requested, func(t *testing.T) {
			t.Parallel()

			env := redirectEnv(t, registered...)

			rec := authorizeTo(env, requested, "code")
			require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
			loc := rec.Header().Get("Location")
			require.True(t, strings.HasPrefix(loc, requested+"?code="), loc)

			code := mustLocation(t, rec).Query().Get("code")
			form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {requested}}
			tok := serve(env.srv.TokenHandler(), boundsPost("/oauth2/token", strings.NewReader(form.Encode())))
			assert.Equal(t, http.StatusOK, tok.Code, "the code is bound to the URI requested: %s", tok.Body.String())
		})
	}

	t.Run("the token request presents the port it was delivered to", func(t *testing.T) {
		t.Parallel()

		env := redirectEnv(t, registered...)

		rec := authorizeTo(env, "http://127.0.0.1:51004/callback", "code")
		code := mustLocation(t, rec).Query().Get("code")
		form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"http://127.0.0.1/callback"}}
		tok := serve(env.srv.TokenHandler(), boundsPost("/oauth2/token", strings.NewReader(form.Encode())))
		assert.Equal(t, http.StatusBadRequest, tok.Code)
		assert.Equal(t, oauth2.CodeInvalidGrant, jsonBody(t, tok)["error"])
	})

	refused := []string{
		"http://127.0.0.1:0/callback",
		"http://127.0.0.1:65536/callback",
		"http://127.0.0.1:051004/callback",
		"http://127.0.0.1:/callback",
		"http://127.0.0.1:x/callback",
		"http://127.0.0.1:+1/callback",
		"http://localhost:51004/callback",
		"https://127.0.0.1:51004/callback",
		"HTTP://127.0.0.1:51004/callback",
		"http://127.0.0.1:51004/callback/x",
		"http://127.0.0.1:51004/callback?y=1",
		"http://127.0.0.1:51004/callback?",
		"http://127.0.0.1:51004/callback#x",
		"http://127.0.0.1:51004/callback#",
		"http://u@127.0.0.1:1/callback",
		"http://127.0.0.1:1@evil.example/callback",
		"http://[::1]:1@evil.example/callback",
		"http://127.0.0.1.evil.example:1/callback",
		"http://127.0.0.2:1/callback",
		"http://127.0.0.10:1/callback",
		"http://0x7f.0.0.1:1/callback",
		"http://[::1%25lo0]:1/callback",
		"http://[0:0:0:0:0:0:0:1]:1/callback",
	}

	for _, requested := range refused {
		t.Run(requested, func(t *testing.T) {
			t.Parallel()

			env := redirectEnv(t, registered...)

			rec := authorizeTo(env, requested, "code")
			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Equal(t, "oauth2: missing or unregistered redirect_uri\n", rec.Body.String())
			assert.Empty(t, rec.Header().Get("Location"))
		})
	}

	t.Run("a registered https URI needs its exact case", func(t *testing.T) {
		t.Parallel()

		env := redirectEnv(t, "https://App.Example/CB")

		assert.Equal(t, http.StatusFound, authorizeTo(env, "https://App.Example/CB", "code").Code)
		assert.Equal(t, http.StatusBadRequest, authorizeTo(env, "https://app.example/cb", "code").Code)
	})
}

// TestAuthorizeNeedsTheRedirectURIOfAClientRegisteringSeveral: a request
// may omit redirect_uri only when the client registered exactly one (RFC
// 6749 §3.1.2.3); otherwise it is a bare 400.
func TestAuthorizeNeedsTheRedirectURIOfAClientRegisteringSeveral(t *testing.T) {
	t.Parallel()

	for _, uris := range [][]string{{}, {"https://app.example/cb", "https://app.example/other"}} {
		env := redirectEnv(t, uris...)

		rec := authorizeTo(env, "", "code")
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, "oauth2: missing or unregistered redirect_uri\n", rec.Body.String())
		assert.Empty(t, rec.Header().Get("Location"))
	}
}
