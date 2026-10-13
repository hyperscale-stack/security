// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// browser is a test client with a cookie jar that does not follow
// redirects.
type browser struct {
	t      *testing.T
	srv    *httptest.Server
	client *http.Client
}

func newBrowser(t *testing.T) *browser {
	t.Helper()

	handler, err := newServer()
	require.NoError(t, err)

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	client := srv.Client()
	client.Jar = jar
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	return &browser{t: t, srv: srv, client: client}
}

// do sends a request with the given headers and returns the status and body.
func (b *browser) do(method, path string, form url.Values, headers map[string]string) (int, string) {
	b.t.Helper()

	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}

	req, err := http.NewRequest(method, b.srv.URL+path, body)
	require.NoError(b.t, err)

	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := b.client.Do(req)
	require.NoError(b.t, err)

	defer func() { _ = resp.Body.Close() }()

	out, err := io.ReadAll(resp.Body)
	require.NoError(b.t, err)

	return resp.StatusCode, string(out)
}

// loginToken opens the sign-in form and returns its CSRF token.
func (b *browser) loginToken() string {
	b.t.Helper()

	status, body := b.do(http.MethodGet, "/login", nil, nil)
	require.Equal(b.t, http.StatusOK, status)

	match := csrfRE.FindStringSubmatch(body)
	require.Len(b.t, match, 2, "the sign-in form must carry a CSRF token")

	return match[1]
}

func (b *browser) signIn(username, password, token string, headers map[string]string) int {
	b.t.Helper()

	status, _ := b.do(http.MethodPost, "/login", url.Values{"username": {username}, "password": {password}, "csrf_token": {token}}, headers)

	return status
}

// Audit CORE-I9: the session-web sign-in form had no CSRF token, so another
// site could sign the victim into the attacker's account (login CSRF). The
// form now carries the token of a session opened for it, and the sign-in
// refuses a request without that session or token.
func TestSessionWebSignInRequiresTheFormToken(t *testing.T) {
	t.Parallel()

	b := newBrowser(t)

	assert.Equal(t, http.StatusForbidden, b.signIn("alice", "alice-secret", "", nil), "no session, no token")

	token := b.loginToken()

	assert.Equal(t, http.StatusForbidden, b.signIn("alice", "alice-secret", "", nil), "no token")
	assert.Equal(t, http.StatusForbidden, b.signIn("alice", "alice-secret", "forged", nil), "forged token")

	status, _ := b.do(http.MethodGet, "/", nil, nil)
	assert.Equal(t, http.StatusSeeOther, status, "the session opened for the form is not a signed-in session")

	assert.Equal(t, http.StatusSeeOther, b.signIn("alice", "alice-secret", token, nil))

	status, body := b.do(http.MethodGet, "/", nil, nil)
	assert.Equal(t, http.StatusOK, status)
	assert.Contains(t, body, "Welcome alice")
}

// net/http's CrossOriginProtection refuses cross-origin unsafe requests from
// their Sec-Fetch-Site and Origin headers, whatever the token.
func TestSessionWebRefusesCrossOriginPosts(t *testing.T) {
	t.Parallel()

	b := newBrowser(t)
	token := b.loginToken()

	assert.Equal(t, http.StatusForbidden, b.signIn("alice", "alice-secret", token, map[string]string{"Sec-Fetch-Site": "cross-site"}))
	assert.Equal(t, http.StatusForbidden, b.signIn("alice", "alice-secret", token, map[string]string{"Origin": "https://evil.example"}))
	assert.Equal(t, http.StatusSeeOther, b.signIn("alice", "alice-secret", token, map[string]string{"Sec-Fetch-Site": "same-origin"}))
}

// Audit CORE-03: the example's login checked the password only for known
// users — 262 µs against 66 ms. It now authenticates through
// basic.Authenticator, which spends one verification on every attempt. Coarse
// bound (fastest of 7 interleaved runs, ratio ≥ 0.5; ≈ 0.004 before).
func TestSessionWebSignInTimeDoesNotRevealAccounts(t *testing.T) {
	b := newBrowser(t)
	token := b.loginToken()
	fastest := map[string]time.Duration{}

	for range 7 {
		for _, username := range []string{"alice", "nobody"} {
			start := time.Now()
			status := b.signIn(username, "wrong", token, nil)
			d := time.Since(start)

			require.Equal(t, http.StatusUnauthorized, status, username)

			if fastest[username] == 0 || d < fastest[username] {
				fastest[username] = d
			}
		}
	}

	ratio := float64(fastest["nobody"]) / float64(fastest["alice"])
	assert.GreaterOrEqual(t, ratio, 0.5, "an unknown user answers %.3f× the time of a known one", ratio)
}

// The sign-in applies the Basic credential rules: a control character never
// reaches the user lookup.
func TestSessionWebSignInRefusesMalformedCredentials(t *testing.T) {
	t.Parallel()

	b := newBrowser(t)
	token := b.loginToken()

	for _, username := range []string{"al\x00ice", "alice\r\nX-Injected: 1", "\xff\xfe", ""} {
		assert.Equal(t, http.StatusUnauthorized, b.signIn(username, "alice-secret", token, nil), "%q", username)
	}
}

func TestNewHTTPServerBoundsSlowClients(t *testing.T) {
	t.Parallel()

	srv := newHTTPServer(":0", http.NotFoundHandler())

	assert.Positive(t, srv.ReadHeaderTimeout)
	assert.Positive(t, srv.ReadTimeout)
	assert.Positive(t, srv.WriteTimeout)
	assert.Positive(t, srv.IdleTimeout)
	assert.Positive(t, srv.MaxHeaderBytes)
}
