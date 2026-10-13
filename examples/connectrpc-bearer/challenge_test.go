// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Audit CORE-10: a Connect unary 401 carried no WWW-Authenticate field
// (RFC 9110 §11.6.1). Audit CORE-02 / decision 6: credentials are read from
// header fields only.
func TestConnectRPCBearerChallenges(t *testing.T) {
	t.Parallel()

	handler, mint, err := newServer()
	require.NoError(t, err)

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	good, err := mint(scope)
	require.NoError(t, err)

	wrongScope, err := mint("other:read")
	require.NoError(t, err)

	call := func(t *testing.T, query string, authorization ...string) (int, []string) {
		t.Helper()

		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
			srv.URL+"/grpc.health.v1.Health/Check"+query, strings.NewReader("{}"))
		require.NoError(t, err)

		req.Header.Set("Content-Type", "application/json")

		for _, v := range authorization {
			req.Header.Add("Authorization", v)
		}

		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())

		return resp.StatusCode, resp.Header.Values("WWW-Authenticate")
	}

	const (
		bare         = `Bearer realm="api"`
		invalidToken = `Bearer realm="api", error="invalid_token", error_description="The access token is invalid or has expired."`
		insufficient = `Bearer realm="api", error="insufficient_scope", error_description="The request requires higher privileges than provided by the access token."`
	)

	cases := []struct {
		name          string
		query         string
		authorization []string
		status        int
		challenge     []string
	}{
		{"no token", "", nil, http.StatusUnauthorized, []string{bare}},
		{"garbage token", "", []string{"Bearer not-a-jwt"}, http.StatusUnauthorized, []string{invalidToken}},
		{"token in the query string", "?Authorization=" + url.QueryEscape("Bearer "+good), nil, http.StatusUnauthorized, []string{bare}},
		{"repeated authorization", "", []string{"Bearer " + good, "Bearer not-a-jwt"}, http.StatusBadRequest,
			[]string{`Bearer realm="api", error="invalid_request", error_description="The request is malformed."`}},
		{"valid token without the scope", "", []string{"Bearer " + wrongScope}, http.StatusForbidden, []string{insufficient}},
		{"valid token", "", []string{"Bearer " + good}, http.StatusOK, nil},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			status, challenge := call(t, c.query, c.authorization...)

			assert.Equal(t, c.status, status)
			assert.Equal(t, c.challenge, challenge)
		})
	}
}
