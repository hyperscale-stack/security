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
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var csrfRE = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

func TestSessionWebExample(t *testing.T) {
	t.Parallel()

	handler, err := newServer()
	require.NoError(t, err)

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	client := srv.Client()
	client.Jar = jar
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse // inspect redirects instead of following them
	}

	get := func(t *testing.T, path string) *http.Response {
		t.Helper()

		resp, err := client.Get(srv.URL + path)
		require.NoError(t, err)

		return resp
	}

	postForm := func(t *testing.T, path string, form url.Values) *http.Response {
		t.Helper()

		resp, err := client.PostForm(srv.URL+path, form)
		require.NoError(t, err)

		return resp
	}

	// 1. The home page redirects to /login when no session cookie is set.
	resp := get(t, "/")
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
	assert.Equal(t, "/login", resp.Header.Get("Location"))
	_ = resp.Body.Close()

	// 2. Wrong password is rejected.
	resp = postForm(t, "/login", url.Values{"username": {"alice"}, "password": {"wrong"}})
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	_ = resp.Body.Close()

	// 3. Correct credentials mint a session and redirect home.
	resp = postForm(t, "/login", url.Values{"username": {"alice"}, "password": {"alice-secret"}})
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
	assert.Equal(t, "/", resp.Header.Get("Location"))
	_ = resp.Body.Close()

	// 4. The home page now renders the authenticated view.
	resp = get(t, "/")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Contains(t, string(body), "Welcome alice")

	match := csrfRE.FindStringSubmatch(string(body))
	require.Len(t, match, 2, "home page must embed a CSRF token")
	csrf := match[1]

	// 5. Logout without the CSRF token is forbidden.
	resp = postForm(t, "/logout", url.Values{"csrf_token": {"forged"}})
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	_ = resp.Body.Close()

	// 6. Logout with the CSRF token clears the session.
	resp = postForm(t, "/logout", url.Values{"csrf_token": {csrf}})
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
	_ = resp.Body.Close()

	// 7. The home page redirects to /login again.
	resp = get(t, "/")
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
	_ = resp.Body.Close()
}

func TestSessionWebTamperedCookieIsDropped(t *testing.T) {
	t.Parallel()

	handler, err := newServer()
	require.NoError(t, err)

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	require.NoError(t, err)
	req.Header.Set("Cookie", "session="+strings.Repeat("A", 80))

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
