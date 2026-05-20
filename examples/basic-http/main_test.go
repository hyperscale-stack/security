// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBasicHTTPExample(t *testing.T) {
	t.Parallel()

	handler, err := newServer()
	require.NoError(t, err)

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	cases := []struct {
		name     string
		path     string
		user     string
		pass     string
		wantCode int
	}{
		{"authenticated identity", "/", "alice", "alice-secret", http.StatusOK},
		{"wrong password", "/", "alice", "nope", http.StatusUnauthorized},
		{"unknown user", "/", "ghost", "whatever", http.StatusUnauthorized},
		{"no credentials", "/", "", "", http.StatusUnauthorized},
		{"admin route denied for plain user", "/admin", "alice", "alice-secret", http.StatusForbidden},
		{"admin route granted for admin", "/admin", "root", "root-secret", http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req, err := http.NewRequest(http.MethodGet, srv.URL+tc.path, nil)
			require.NoError(t, err)

			if tc.user != "" {
				req.SetBasicAuth(tc.user, tc.pass)
			}

			resp, err := srv.Client().Do(req)
			require.NoError(t, err)
			t.Cleanup(func() { _ = resp.Body.Close() })

			assert.Equal(t, tc.wantCode, resp.StatusCode)
		})
	}
}
