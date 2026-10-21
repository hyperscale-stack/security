// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/clientauth"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/hyperscale-stack/security/oauth2/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// metadataServer is a server of issuer with grants, configured further by
// configure.
func metadataServer(t *testing.T, issuer string, grants []oauth2.Grant, configure func(*oauth2.ServerConfig)) (*oauth2.Server, error) {
	t.Helper()

	cfg := oauth2.ServerConfig{
		Profile: oauth2.Profile20, Storage: memory.New(), ClientStore: &staticClientStore{},
		IssuerResolver: oauth2.StaticIssuer(issuer, "api"), Grants: grants,
		ClientAuth: []oauth2.ClientAuthenticator{clientauth.NewBasic()},
	}

	if configure != nil {
		configure(&cfg)
	}

	return oauth2.NewServer(cfg)
}

// rawMetadata returns the RFC 8414 document srv serves, as sent.
func rawMetadata(t *testing.T, srv *oauth2.Server) string {
	t.Helper()

	rec := serve(srv.MetadataHandler(), httptest.NewRequest(http.MethodGet, metadataPath, nil))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	return rec.Body.String()
}

// TestMetadataScopesSupported pins RFC 8414 §2 scopes_supported
// (RECOMMENDED): published in order when ServerConfig.ScopesSupported is
// set, omitted otherwise — and what NewServer checked is what is served,
// whatever the caller later does to its slice or to Config's.
func TestMetadataScopesSupported(t *testing.T) {
	t.Parallel()

	srv, err := metadataServer(t, testIssuer, nil, nil)
	require.NoError(t, err)
	assert.NotContains(t, metadataOf(t, srv), "scopes_supported")

	scopes := []string{"read", "write", "openid"}
	srv, err = metadataServer(t, testIssuer, nil, func(c *oauth2.ServerConfig) { c.ScopesSupported = scopes })
	require.NoError(t, err)

	want := []any{"read", "write", "openid"}
	assert.Equal(t, want, metadataOf(t, srv)["scopes_supported"])

	scopes[0] = "a b"
	srv.Config().ScopesSupported[1] = "c d"
	assert.Equal(t, want, metadataOf(t, srv)["scopes_supported"], "neither slice changes what is served")
}

// TestNewServerValidatesScopesSupported: every ScopesSupported value is one
// RFC 6749 §3.3 scope token (NQCHAR, no SP), listed once.
func TestNewServerValidatesScopesSupported(t *testing.T) {
	t.Parallel()

	for _, scopes := range [][]string{{""}, {"a b"}, {" read"}, {`a"b`}, {`a\b`}, {"é"}, {"read", "read"}} {
		_, err := metadataServer(t, testIssuer, nil, func(c *oauth2.ServerConfig) { c.ScopesSupported = scopes })
		require.ErrorContains(t, err, "ScopesSupported", "%q", scopes)
	}
}

// TestMetadataAdvertisesJWKSURIOnlyWhenServed pins RFC 8414 §2 jwks_uri,
// the URL "of the authorization server's JWK Set document": the oauth2
// module serves none, so the metadata publishes it — the issuer, a trailing
// "/" removed, and /.well-known/jwks.json — only with AdvertiseJWKSURI.
func TestMetadataAdvertisesJWKSURIOnlyWhenServed(t *testing.T) {
	t.Parallel()

	srv, err := metadataServer(t, testIssuer, nil, nil)
	require.NoError(t, err)
	assert.NotContains(t, metadataOf(t, srv), "jwks_uri")

	for issuer, want := range map[string]string{
		testIssuer:                     testIssuer + "/.well-known/jwks.json",
		"https://auth.example/tenant/": "https://auth.example/tenant/.well-known/jwks.json",
	} {
		srv, err := metadataServer(t, issuer, nil, func(c *oauth2.ServerConfig) { c.AdvertiseJWKSURI = true })
		require.NoError(t, err)
		assert.Equal(t, want, metadataOf(t, srv)["jwks_uri"])
	}
}

// TestMetadataWithoutAuthorizationFlow pins RFC 8414 §2 for a server
// without the authorization_code grant: authorization_endpoint is
// "REQUIRED unless no grant types are supported that use the authorization
// endpoint", and the REQUIRED arrays are empty — never null, never omitted
// (an omitted grant_types_supported would mean ["authorization_code",
// "implicit"], response_modes_supported ["query", "fragment"]). An enabled
// implicit flow is the only authorization flow then: the token response
// type, without PKCE methods.
func TestMetadataWithoutAuthorizationFlow(t *testing.T) {
	t.Parallel()

	gcfg := grant.Config{Storage: memory.New(), AccessTokens: token.NewOpaque(32), AccessTTL: time.Hour}

	for name, tc := range map[string]struct {
		grants     []oauth2.Grant
		grantTypes string
	}{
		"no grant":                {nil, `"grant_types_supported":[]`},
		"client_credentials only": {[]oauth2.Grant{grant.NewClientCredentials(gcfg)}, `"grant_types_supported":["client_credentials"]`},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv, err := metadataServer(t, testIssuer, tc.grants, nil)
			require.NoError(t, err)

			raw := rawMetadata(t, srv)
			assert.Contains(t, raw, tc.grantTypes)
			assert.Contains(t, raw, `"response_types_supported":[]`)
			assert.Contains(t, raw, `"response_modes_supported":[]`)
			assert.Contains(t, raw, `"authorization_response_iss_parameter_supported":false`)
			assert.NotContains(t, raw, "authorization_endpoint")
			assert.NotContains(t, raw, "code_challenge_methods_supported")
		})
	}

	t.Run("implicit only", func(t *testing.T) {
		t.Parallel()

		srv, err := metadataServer(t, testIssuer, []oauth2.Grant{grant.NewClientCredentials(gcfg)}, nil)
		require.NoError(t, err)

		_ = srv.AuthorizeHandler(oauth2.AuthorizeConfig{AllowImplicit: true, ImplicitTokens: implicitTokens()}, approve)

		doc := metadataOf(t, srv)
		assert.Equal(t, testIssuer+"/oauth2/authorize", doc["authorization_endpoint"])
		assert.Equal(t, []any{"token"}, doc["response_types_supported"])
		assert.Equal(t, []any{"query", "fragment"}, doc["response_modes_supported"])
		assert.Equal(t, []any{"client_credentials", "implicit"}, doc["grant_types_supported"])
		assert.Equal(t, true, doc["authorization_response_iss_parameter_supported"])
		assert.NotContains(t, doc, "code_challenge_methods_supported")
	})
}
