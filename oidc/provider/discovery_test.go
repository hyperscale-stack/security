// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/clientauth"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/token"
	oidcprovider "github.com/hyperscale-stack/security/oidc/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// discovery fetches and decodes the discovery document.
func discovery(t *testing.T, e *env, r *http.Request) map[string]any {
	t.Helper()

	rec := serve(e.op.DiscoveryHandler(), r)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var doc map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &doc))

	return doc
}

// TestDiscoveryDocument pins OIDC Discovery 1.0 §3 and §4.2: the REQUIRED
// members, only implemented capabilities, request_uri_parameter_supported
// published false (omitted, it would mean true), response_modes_supported
// published (omitted, it would add fragment), and no other member.
func TestDiscoveryDocument(t *testing.T) {
	t.Parallel()

	e := newEnv(t)

	rec := serve(e.op.DiscoveryHandler(), get("/.well-known/openid-configuration"))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Equal(t, "max-age=300", rec.Header().Get("Cache-Control"))

	assert.JSONEq(t, `{
		"issuer": "https://op.example",
		"authorization_endpoint": "https://op.example/oauth2/authorize",
		"token_endpoint": "https://op.example/oauth2/token",
		"userinfo_endpoint": "https://op.example/oauth2/userinfo",
		"jwks_uri": "https://op.example/.well-known/jwks.json",
		"revocation_endpoint": "https://op.example/oauth2/revoke",
		"introspection_endpoint": "https://op.example/oauth2/introspect",
		"scopes_supported": ["openid", "profile", "email", "address", "phone", "offline_access"],
		"response_types_supported": ["code"],
		"response_modes_supported": ["query"],
		"grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
		"subject_types_supported": ["public"],
		"id_token_signing_alg_values_supported": ["RS256", "ES256"],
		"token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
		"revocation_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
		"introspection_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
		"code_challenge_methods_supported": ["S256"],
		"claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "at_hash"],
		"claims_parameter_supported": true,
		"request_parameter_supported": false,
		"request_uri_parameter_supported": false,
		"authorization_response_iss_parameter_supported": true
	}`, rec.Body.String())
}

// TestDiscoveryPathIssuers pins OIDC Discovery §4.1 / Core §16.15: a path
// issuer is kept verbatim (terminating slash included) and its endpoints
// are built under its path, one terminating slash removed.
func TestDiscoveryPathIssuers(t *testing.T) {
	t.Parallel()

	for _, issuer := range []string{"https://op.example/tenant-a", "https://op.example/tenant-a/"} {
		e := newEnv(t, withResolver(fixedIssuer{issuer: issuer}))
		doc := discovery(t, e, get("/tenant-a/.well-known/openid-configuration"))

		assert.Equal(t, issuer, doc["issuer"])
		assert.Equal(t, "https://op.example/tenant-a/oauth2/authorize", doc["authorization_endpoint"])
		assert.Equal(t, "https://op.example/tenant-a/oauth2/userinfo", doc["userinfo_endpoint"])
		assert.Equal(t, "https://op.example/tenant-a/.well-known/jwks.json", doc["jwks_uri"])
	}
}

func TestDiscoveryRoutePrefix(t *testing.T) {
	t.Parallel()

	for prefix, want := range map[string]string{
		"/connect": "https://op.example/connect/token",
		"/":        "https://op.example/token",
	} {
		e := newEnv(t, withRoutePrefix(prefix))
		assert.Equal(t, want, discovery(t, e, get("/.well-known/openid-configuration"))["token_endpoint"], prefix)
	}
}

func TestDiscoveryPKCEMethodsFollowTheProfile(t *testing.T) {
	t.Parallel()

	bcp := discovery(t, newEnv(t), get("/.well-known/openid-configuration"))
	assert.Equal(t, []any{"S256"}, bcp["code_challenge_methods_supported"])

	legacy := discovery(t, newEnv(t, withProfile(oauth2.Profile20)), get("/.well-known/openid-configuration"))
	assert.Equal(t, []any{"S256", "plain"}, legacy["code_challenge_methods_supported"])
}

// TestDiscoveryAdvertisesOfflineAccessWithARefreshGrantOnly: no refresh
// token can be issued without a refresh_token grant, so offline_access is
// not a capability then.
func TestDiscoveryAdvertisesOfflineAccessWithARefreshGrantOnly(t *testing.T) {
	t.Parallel()

	doc := discovery(t, newEnv(t, withoutRefreshGrant()), get("/.well-known/openid-configuration"))
	assert.Equal(t, []any{"openid", "profile", "email", "address", "phone"}, doc["scopes_supported"])
	assert.Equal(t, []any{"authorization_code", "client_credentials"}, doc["grant_types_supported"])
}

func TestDiscoveryAlgorithmsComeFromTheSigningKeys(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	e.keys.set(oidcprovider.KeyRing{Signing: []jwtsec.PrivateKey{signingEC(), signingRSA()}})

	doc := discovery(t, e, get("/.well-known/openid-configuration"))
	assert.Equal(t, []any{"RS256", "ES256"}, doc["id_token_signing_alg_values_supported"], "RS256 first")

	e.keys.set(oidcprovider.KeyRing{
		Signing:   []jwtsec.PrivateKey{signingRSA()},
		Published: []jwtsec.PublicKey{publicOf(signingEC())},
	})
	doc = discovery(t, e, get("/.well-known/openid-configuration"))
	assert.Equal(t, []any{"RS256"}, doc["id_token_signing_alg_values_supported"], "published-only keys sign nothing")
}

func TestDiscoveryOptionalMembers(t *testing.T) {
	t.Parallel()

	e := newEnv(t, withConfig(func(c *oidcprovider.Config) {
		c.ACRValuesSupported = []string{"urn:example:loa:2", "urn:example:loa:3"}
		c.ClaimsSupported = []string{"name", "email", "sub", "groups"}
	}))

	doc := discovery(t, e, get("/.well-known/openid-configuration"))
	assert.Equal(t, []any{"urn:example:loa:2", "urn:example:loa:3"}, doc["acr_values_supported"])
	assert.Equal(t, []any{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "at_hash", "name", "email", "groups"},
		doc["claims_supported"], "application claims appended, duplicates dropped")

	plain := discovery(t, newEnv(t), get("/.well-known/openid-configuration"))
	assert.NotContains(t, plain, "acr_values_supported", "a member with zero elements is omitted (Discovery §4.2)")
}

func TestDiscoveryFailsClosed(t *testing.T) {
	t.Parallel()

	cases := map[string]envOption{
		"resolver error": withResolver(fixedIssuer{err: errors.New("no tenant")}),
		"invalid issuer": withResolver(fixedIssuer{issuer: "https://op.example?x=1"}),
	}

	for name, opt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			e := newEnv(t, opt)
			rec := serve(e.op.DiscoveryHandler(), get("/.well-known/openid-configuration"))
			assert.Equal(t, http.StatusInternalServerError, rec.Code)
			assert.NotEmpty(t, e.sink.all())
		})
	}

	t.Run("key source error", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t)
		e.keys.fail(errors.New("kms down"))

		rec := serve(e.op.DiscoveryHandler(), get("/.well-known/openid-configuration"))
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("methods", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t)
		assert.Equal(t, http.StatusOK,
			serve(e.op.DiscoveryHandler(), httptest.NewRequest(http.MethodHead, "/.well-known/openid-configuration", nil)).Code)

		post := serve(e.op.DiscoveryHandler(), httptest.NewRequest(http.MethodPost, "/.well-known/openid-configuration", nil))
		assert.Equal(t, http.StatusMethodNotAllowed, post.Code)
		assert.Equal(t, "GET, HEAD", post.Header().Get("Allow"))
	})
}

// withClientAuth replaces the server's client authentication methods.
func withClientAuth(auths ...oauth2.ClientAuthenticator) envOption {
	return func(s *oauth2.ServerConfig, _ *grant.Config, _ *oidcprovider.Config) { s.ClientAuth = auths }
}

// TestDiscoveryConsistentWithRFC8414Metadata pins RFC 9068 §4: values
// published through RFC 8414 and OpenID Connect Discovery MUST be
// consistent. Every member of the RFC 8414 document is published alike;
// the authentication methods of /revoke and /introspect are also omitted
// alike, since their omission has a meaning of its own (RFC 8414 §2).
func TestDiscoveryConsistentWithRFC8414Metadata(t *testing.T) {
	t.Parallel()

	// attemptImplicit tries to enable the implicit flow, which the provider
	// refuses (UD-1): the documents must stay consistent all the same.
	attemptImplicit := func(e *env) {
		defer func() { _ = recover() }()

		e.op.AuthorizeHandler(oauth2.AuthorizeConfig{
			AllowImplicit: true, ImplicitTokens: token.OpaqueRefreshAdapter{Opaque: token.NewOpaque(32)},
		})
	}

	cases := map[string]struct {
		opts  []envOption
		setup func(*env)
	}{
		"default routes":      {},
		"route prefix":        {opts: []envOption{withRoutePrefix("/connect")}},
		"public clients only": {opts: []envOption{withClientAuth(clientauth.NewNone())}},
		"deployment scopes": {opts: []envOption{func(s *oauth2.ServerConfig, _ *grant.Config, _ *oidcprovider.Config) {
			s.ScopesSupported = []string{"api:read", "openid"}
		}}},
		"implicit flow attempted (Profile20)": {
			opts: []envOption{withProfile(oauth2.Profile20)}, setup: attemptImplicit,
		},
	}

	for name, tc := range cases {
		e := newEnv(t, append(tc.opts, withResolver(fixedIssuer{issuer: "https://op.example/tenant-a"}))...)

		if tc.setup != nil {
			tc.setup(e)
		}

		oidc := discovery(t, e, get("/tenant-a/.well-known/openid-configuration"))

		rec := serve(e.op.Server().MetadataHandler(), get("/.well-known/oauth-authorization-server/tenant-a"))
		require.Equal(t, http.StatusOK, rec.Code, name)

		var rfc8414 map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &rfc8414))

		for member, v := range rfc8414 {
			assert.Equal(t, v, oidc[member], "%s: %s", name, member)
		}

		// The provider serves its JWK Set and its scopes: the RFC 8414
		// document publishes them too.
		for _, member := range []string{"jwks_uri", "scopes_supported"} {
			assert.Contains(t, rfc8414, member, "%s: %s", name, member)
		}

		for _, member := range []string{"revocation_endpoint_auth_methods_supported", "introspection_endpoint_auth_methods_supported"} {
			_, inOIDC := oidc[member]
			_, inRFC8414 := rfc8414[member]
			assert.Equal(t, inRFC8414, inOIDC, "%s: %s published alike", name, member)
		}
	}
}

// TestDiscoveryPublishesTheDeploymentScopes: scopes_supported (Discovery
// §3, RFC 8414 §2) lists the OpenID Connect scopes the provider serves,
// then the server's own ServerConfig.ScopesSupported, each once — in both
// metadata documents.
func TestDiscoveryPublishesTheDeploymentScopes(t *testing.T) {
	t.Parallel()

	e := newEnv(t, func(s *oauth2.ServerConfig, _ *grant.Config, _ *oidcprovider.Config) {
		s.ScopesSupported = []string{"api:read", "openid"}
	})

	want := []any{"openid", "profile", "email", "address", "phone", "offline_access", "api:read"}
	assert.Equal(t, want, discovery(t, e, get("/.well-known/openid-configuration"))["scopes_supported"])

	rec := serve(e.op.Server().MetadataHandler(), get("/.well-known/oauth-authorization-server"))
	require.Equal(t, http.StatusOK, rec.Code)

	var rfc8414 map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &rfc8414))
	assert.Equal(t, want, rfc8414["scopes_supported"])
}
