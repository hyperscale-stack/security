// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Audit CORE-I5 (probe TestZZAuditMultipleAuthorizationHeaders): with a good
// and a bad Authorization line the first one silently won (RFC 9110 §5.3).
func TestBasicHTTPRefusesARepeatedAuthorizationField(t *testing.T) {
	t.Parallel()

	handler, err := newServer()
	require.NoError(t, err)

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	good := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:alice-secret"))
	bad := "Basic " + base64.StdEncoding.EncodeToString([]byte("root:nope"))

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	require.NoError(t, err)
	req.Header.Add("Authorization", good)
	req.Header.Add("Authorization", bad)

	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
