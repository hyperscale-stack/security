// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConnectRPCBearerExample(t *testing.T) {
	t.Parallel()

	handler, mint, err := newServer()
	require.NoError(t, err)

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	goodToken, err := mint(scope)
	require.NoError(t, err)

	wrongScopeToken, err := mint("other:read")
	require.NoError(t, err)

	// check performs a Connect unary call against the health Check endpoint
	// and returns the HTTP status code. The Connect protocol maps the error
	// code onto the HTTP status (Unauthenticated -> 401, PermissionDenied ->
	// 403), so the status alone tells the outcome apart.
	check := func(t *testing.T, token string) int {
		t.Helper()

		req, err := http.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			srv.URL+"/grpc.health.v1.Health/Check",
			strings.NewReader("{}"),
		)
		require.NoError(t, err)

		req.Header.Set("Content-Type", "application/json")

		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}

		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())

		return resp.StatusCode
	}

	t.Run("valid token with the right scope succeeds", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, http.StatusOK, check(t, goodToken))
	})

	t.Run("missing token is unauthorized", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, http.StatusUnauthorized, check(t, ""))
	})

	t.Run("garbage token is unauthorized", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, http.StatusUnauthorized, check(t, "not-a-jwt"))
	})

	t.Run("valid token without the scope is forbidden", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, http.StatusForbidden, check(t, wrongScopeToken))
	})
}
