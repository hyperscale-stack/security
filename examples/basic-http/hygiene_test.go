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

// Audit CORE-I9: the Basic demo answered with a Bearer challenge, and its
// server had no timeouts.
func TestBasicHTTPChallengesWithBasic(t *testing.T) {
	t.Parallel()

	handler, err := newServer()
	require.NoError(t, err)

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	for name, creds := range map[string][2]string{"no credentials": {}, "wrong password": {"alice", "nope"}} {
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
		require.NoError(t, err)

		if creds[0] != "" {
			req.SetBasicAuth(creds[0], creds[1])
		}

		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, name)
		assert.Equal(t, []string{`Basic realm="basic-http", charset="UTF-8"`}, resp.Header.Values("WWW-Authenticate"), name)
	}
}

func TestNewHTTPServerBoundsSlowClients(t *testing.T) {
	t.Parallel()

	srv := newHTTPServer(":0", http.NotFoundHandler())

	assert.Positive(t, srv.ReadHeaderTimeout)
	assert.Positive(t, srv.ReadTimeout)
	assert.Positive(t, srv.WriteTimeout)
	assert.Positive(t, srv.IdleTimeout)
	assert.Positive(t, srv.MaxHeaderBytes)
}
