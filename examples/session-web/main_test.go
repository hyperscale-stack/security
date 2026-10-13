// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var csrfRE = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

func TestSessionWebExample(t *testing.T) {
	t.Parallel()

	b := newBrowser(t)

	// 1. The home page redirects to /login when no session cookie is set.
	status, _ := b.do(http.MethodGet, "/", nil, nil)
	assert.Equal(t, http.StatusSeeOther, status)

	// 2. Wrong password is rejected.
	token := b.loginToken()
	assert.Equal(t, http.StatusUnauthorized, b.signIn("alice", "wrong", token, nil))

	// 3. Correct credentials mint a session and redirect home.
	assert.Equal(t, http.StatusSeeOther, b.signIn("alice", "alice-secret", token, nil))

	// 4. The home page now renders the authenticated view.
	status, body := b.do(http.MethodGet, "/", nil, nil)
	require.Equal(t, http.StatusOK, status)
	assert.Contains(t, body, "Welcome alice")

	match := csrfRE.FindStringSubmatch(body)
	require.Len(t, match, 2, "home page must embed a CSRF token")
	csrf := match[1]
	assert.NotEqual(t, token, csrf, "signing in minted a fresh session and token")

	// 5. Logout without the CSRF token is forbidden.
	status, _ = b.do(http.MethodPost, "/logout", url.Values{"csrf_token": {"forged"}}, nil)
	assert.Equal(t, http.StatusForbidden, status)

	// 6. Logout with the CSRF token clears the session.
	status, _ = b.do(http.MethodPost, "/logout", url.Values{"csrf_token": {csrf}}, nil)
	assert.Equal(t, http.StatusSeeOther, status)

	// 7. The home page redirects to /login again.
	status, _ = b.do(http.MethodGet, "/", nil, nil)
	assert.Equal(t, http.StatusSeeOther, status)
}

func TestSessionWebTamperedCookieIsDropped(t *testing.T) {
	t.Parallel()

	handler, err := newServer()
	require.NoError(t, err)

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	require.NoError(t, err)
	req.Header.Set("Cookie", "__Host-session="+strings.Repeat("A", 80)) // the default session cookie name

	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err := client.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })

	// A garbage cookie must not panic — it is treated as "no session".
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
}
