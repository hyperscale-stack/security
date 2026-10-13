// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Audit CORE-02 (probe examples/session-web): a session was accepted from the
// query string — a link logged a cookie-less browser into the attacker's
// session — and from a header named like the cookie.
func TestSessionWebReadsTheSessionFromItsCookieOnly(t *testing.T) {
	t.Parallel()

	b := newBrowser(t)
	require.Equal(t, http.StatusSeeOther, b.signIn("alice", "alice-secret", b.loginToken(), nil))

	srvURL, err := url.Parse(b.srv.URL)
	require.NoError(t, err)

	cookies := b.client.Jar.Cookies(srvURL)
	require.Len(t, cookies, 1)
	cookie := cookies[0]

	srv := b.srv
	// A client without the browser's cookie jar (srv.Client() would return
	// the same client).
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	inQuery, err := http.NewRequest(http.MethodGet, srv.URL+"/?"+cookie.Name+"="+url.QueryEscape(cookie.Value), nil)
	require.NoError(t, err)

	inHeader, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	require.NoError(t, err)
	inHeader.Header.Set(cookie.Name, cookie.Value)

	inCookie, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	require.NoError(t, err)
	inCookie.AddCookie(cookie)

	for name, c := range map[string]struct {
		req  *http.Request
		want int
	}{
		"query string":  {inQuery, http.StatusSeeOther},
		"header":        {inHeader, http.StatusSeeOther},
		"cookie (ctrl)": {inCookie, http.StatusOK},
	} {
		r, err := client.Do(c.req)
		require.NoError(t, err, name)
		_ = r.Body.Close()

		assert.Equal(t, c.want, r.StatusCode, name)
	}
}
