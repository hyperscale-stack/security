// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Audit CORE-02 (probe TestZZAuditBearerTokenFromQueryAndCookie): a bearer
// token was accepted from ?Authorization=… and from a cookie, contrary to
// RFC 6750 §5.3 and to the bearer package documentation.
func TestBearerJWTReadsTheTokenFromTheAuthorizationHeaderOnly(t *testing.T) {
	t.Parallel()

	handler, mint, err := newServer()
	require.NoError(t, err)

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	token, err := mint("resource:read", time.Now())
	require.NoError(t, err)

	bearer := "Bearer " + token

	inQuery, err := http.NewRequest(http.MethodGet, srv.URL+"/?Authorization="+url.QueryEscape(bearer), nil)
	require.NoError(t, err)

	inCookie, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	require.NoError(t, err)
	inCookie.Header.Set("Cookie", `Authorization="`+bearer+`"`)

	inHeader, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	require.NoError(t, err)
	inHeader.Header.Set("Authorization", bearer)

	for name, c := range map[string]struct {
		req  *http.Request
		want int
	}{
		"query string":  {inQuery, http.StatusUnauthorized},
		"cookie":        {inCookie, http.StatusUnauthorized},
		"header (ctrl)": {inHeader, http.StatusOK},
	} {
		r, err := srv.Client().Do(c.req)
		require.NoError(t, err, name)
		_ = r.Body.Close()

		assert.Equal(t, c.want, r.StatusCode, name)
	}
}
