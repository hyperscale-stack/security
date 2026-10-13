// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Audit CORE-I9: the demo exposed an unauthenticated /token endpoint that
// minted access tokens for anyone. Tokens are now minted in-process and the
// demo writes its token to a file only the current user can read.
func TestBearerJWTHasNoPublicTokenEndpoint(t *testing.T) {
	t.Parallel()

	handler, _, err := newServer()
	require.NoError(t, err)

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Post(srv.URL+"/token", "", nil)
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// The demo never prints its token: it writes it to a 0600 file and logs the
// path.
func TestWriteDemoToken(t *testing.T) {
	t.Parallel()

	path, err := writeDemoToken(t.TempDir(), "secret-token")
	require.NoError(t, err)

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	content, err := os.ReadFile(filepath.Clean(path))
	require.NoError(t, err)
	assert.Equal(t, "secret-token", string(content))

	_, err = writeDemoToken(filepath.Join(t.TempDir(), "missing"), "x")
	require.Error(t, err)
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

// Demo tokens are short-lived.
func TestDemoTokensAreShortLived(t *testing.T) {
	t.Parallel()

	assert.LessOrEqual(t, tokenLifetime, 15*time.Minute)
}
