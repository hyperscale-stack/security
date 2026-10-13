// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Audit CORE-02 (probe TestZZAuditBasicCredentialsFromQueryAndCookie): Basic
// credentials were accepted from ?Authorization=… and from a cookie.
func TestBasicHTTPReadsCredentialsFromTheAuthorizationHeaderOnly(t *testing.T) {
	t.Parallel()

	handler, err := newServer()
	require.NoError(t, err)

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	creds := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:alice-secret"))

	inQuery, err := http.NewRequest(http.MethodGet, srv.URL+"/?Authorization="+url.QueryEscape(creds), nil)
	require.NoError(t, err)

	inCookie, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	require.NoError(t, err)
	inCookie.Header.Set("Cookie", `Authorization="`+creds+`"`)

	inHeader, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	require.NoError(t, err)
	inHeader.Header.Set("Authorization", creds)

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
