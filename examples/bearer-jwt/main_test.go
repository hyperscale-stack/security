// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBearerJWTExample(t *testing.T) {
	t.Parallel()

	handler, mint, err := newServer()
	require.NoError(t, err)

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	// Mint a token the way the demo does at start-up.
	token, err := mint("resource:read", time.Now())
	require.NoError(t, err)
	require.NotEmpty(t, token)

	get := func(t *testing.T, path, token string) int {
		t.Helper()

		req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		require.NoError(t, err)

		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}

		r, err := srv.Client().Do(req)
		require.NoError(t, err)
		t.Cleanup(func() { _ = r.Body.Close() })

		return r.StatusCode
	}

	t.Run("valid token reaches the protected route", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, http.StatusOK, get(t, "/", token))
	})

	t.Run("valid token carries the resource:read scope", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, http.StatusOK, get(t, "/reports", token))
	})

	t.Run("missing token is rejected", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, http.StatusUnauthorized, get(t, "/", ""))
	})

	t.Run("garbage token is rejected", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, http.StatusUnauthorized, get(t, "/", "not-a-jwt"))
	})
}
