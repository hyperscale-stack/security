// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBearerJWTExample(t *testing.T) {
	t.Parallel()

	handler, err := newServer()
	require.NoError(t, err)

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	// Mint a token via the public /token endpoint.
	resp, err := srv.Client().Post(srv.URL+"/token", "", nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var minted struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&minted))
	require.NotEmpty(t, minted.AccessToken)

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
		assert.Equal(t, http.StatusOK, get(t, "/", minted.AccessToken))
	})

	t.Run("valid token carries the resource:read scope", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, http.StatusOK, get(t, "/reports", minted.AccessToken))
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
