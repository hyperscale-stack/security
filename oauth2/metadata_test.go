// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/clientauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// metadataPath is where the tests request the RFC 8414 document.
const metadataPath = "/.well-known/oauth-authorization-server"

// metadataOf returns the RFC 8414 document srv serves.
func metadataOf(t *testing.T, srv *oauth2.Server) map[string]any {
	t.Helper()

	rec := serve(srv.MetadataHandler(), httptest.NewRequest(http.MethodGet, metadataPath, nil))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var doc map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &doc))

	return doc
}

// TestMetadataReflectsTheServer pins RFC 8414 §2 against what the server
// serves: the response types and modes of the flows its AuthorizeHandlers
// run, the grant types it registers — sorted, "implicit" (RFC 7591 §2)
// once the implicit flow is enabled — and the client authentication
// methods of /revoke and /introspect, whose omission would mean
// client_secret_basic and nothing respectively; /introspect answers
// confidential clients only, so "none" is not one of its methods.
func TestMetadataReflectsTheServer(t *testing.T) {
	t.Parallel()

	allMethods := []any{"client_secret_basic", "client_secret_post", "none"}

	t.Run("code flow", func(t *testing.T) {
		t.Parallel()

		env := newBoundsEnv(t, 0, nil, nil)
		_ = env.srv.AuthorizeHandler(oauth2.AuthorizeConfig{}, approve)

		doc := metadataOf(t, env.srv)
		assert.Equal(t, []any{"code"}, doc["response_types_supported"])
		assert.Equal(t, []any{"query"}, doc["response_modes_supported"])
		assert.Equal(t, []any{"authorization_code", "client_credentials", "refresh_token"}, doc["grant_types_supported"])
		assert.Equal(t, allMethods, doc["token_endpoint_auth_methods_supported"])
		assert.Equal(t, allMethods, doc["revocation_endpoint_auth_methods_supported"])
		assert.Equal(t, []any{"client_secret_basic", "client_secret_post"}, doc["introspection_endpoint_auth_methods_supported"])
	})

	t.Run("implicit flow enabled", func(t *testing.T) {
		t.Parallel()

		env := newBoundsEnv(t, 0, nil, nil)
		_ = env.authorizeHandler(approve)

		doc := metadataOf(t, env.srv)
		assert.Equal(t, []any{"code", "token"}, doc["response_types_supported"])
		assert.Equal(t, []any{"query", "fragment"}, doc["response_modes_supported"])
		assert.Equal(t, []any{"authorization_code", "client_credentials", "implicit", "refresh_token"}, doc["grant_types_supported"])
	})

	t.Run("grant types are sorted", func(t *testing.T) {
		t.Parallel()

		env := newBoundsEnv(t, 0, nil, nil)

		// Map iteration order varies from one call to the next: ask often.
		for range 32 {
			assert.Equal(t, []any{"authorization_code", "client_credentials", "refresh_token"},
				metadataOf(t, env.srv)["grant_types_supported"])
		}
	})

	t.Run("public clients only", func(t *testing.T) {
		t.Parallel()

		cfg := newBoundsEnv(t, 0, nil, nil).srv.Config()
		cfg.ClientAuth = []oauth2.ClientAuthenticator{clientauth.NewNone()}

		srv, err := oauth2.NewServer(cfg)
		require.NoError(t, err)

		doc := metadataOf(t, srv)
		assert.Equal(t, []any{"none"}, doc["revocation_endpoint_auth_methods_supported"])
		assert.NotContains(t, doc, "introspection_endpoint_auth_methods_supported",
			"no method authenticates a confidential client")
	})
}

// TestMetadataAnswersGETAndHEADOnly: the document is retrieved with GET
// (RFC 8414 §3.1); HEAD gets its headers, any other method 405 listing the
// two in Allow (RFC 9110 §15.5.6).
func TestMetadataAnswersGETAndHEADOnly(t *testing.T) {
	t.Parallel()

	env := newBoundsEnv(t, 0, nil, nil)

	rec := serve(env.srv.MetadataHandler(), httptest.NewRequest(http.MethodHead, metadataPath, nil))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions} {
		rec := serve(env.srv.MetadataHandler(), httptest.NewRequest(method, metadataPath, nil))
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code, method)
		assert.Equal(t, "GET, HEAD", rec.Header().Get("Allow"), method)
		assert.NotContains(t, rec.Body.String(), "issuer", method)
	}
}
