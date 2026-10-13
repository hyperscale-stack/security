// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/clientauth"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/hyperscale-stack/security/oauth2/token"
	oidcprovider "github.com/hyperscale-stack/security/oidc/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// noopExtension stands for an extension the application registered itself.
type noopExtension struct{}

func (noopExtension) ValidateAuthorizeRequest(context.Context, *http.Request, *oauth2.AuthorizeRequest) (any, error) {
	return nil, nil
}

func (noopExtension) CompleteAuthorization(context.Context, *oauth2.AuthorizeRequest, oauth2.Consent, time.Time) (oauth2.ExtensionGrant, error) {
	return oauth2.ExtensionGrant{}, nil
}

func (noopExtension) ExtendTokenResponse(context.Context, oauth2.TokenIssuance) (oauth2.TokenResponseExtension, error) {
	return oauth2.TokenResponseExtension{}, nil
}

func baseServerConfig() oauth2.ServerConfig {
	store := memory.New()
	gcfg := grant.Config{Storage: store, AccessTokens: token.NewOpaque(32), AccessTTL: time.Hour}

	return oauth2.ServerConfig{
		Storage:        store,
		ClientStore:    testClients(),
		IssuerResolver: oauth2.StaticIssuer(testIssuer, "api"),
		ClientAuth:     []oauth2.ClientAuthenticator{clientauth.NewBasic()},
		Grants:         []oauth2.Grant{grant.NewAuthorizationCode(gcfg)},
	}
}

func baseConfig() oidcprovider.Config {
	clock := newTestClock()

	return oidcprovider.Config{
		Keys: newMutableKeys(defaultRing()), Claims: newFakeClaims(), Interaction: newFakeInteraction(clock),
	}
}

func TestNewValidatesItsConfiguration(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		server func(*oauth2.ServerConfig)
		config func(*oidcprovider.Config)
	}{
		{"no key source", nil, func(c *oidcprovider.Config) { c.Keys = nil }},
		{"no claims source", nil, func(c *oidcprovider.Config) { c.Claims = nil }},
		{"no interaction", nil, func(c *oidcprovider.Config) { c.Interaction = nil }},
		{"negative ID Token lifetime", nil, func(c *oidcprovider.Config) { c.IDTokenTTL = -time.Second }},
		{"empty supported claim", nil, func(c *oidcprovider.Config) { c.ClaimsSupported = []string{"name", ""} }},
		{"supported claim with a control character", nil, func(c *oidcprovider.Config) { c.ClaimsSupported = []string{"na\nme"} }},
		{"supported claim never released: azp", nil, func(c *oidcprovider.Config) { c.ClaimsSupported = []string{"azp"} }},
		{"supported claim never released: _claim_sources", nil, func(c *oidcprovider.Config) { c.ClaimsSupported = []string{"_claim_sources"} }},
		{"supported claim never released: a tagged sub", nil, func(c *oidcprovider.Config) { c.ClaimsSupported = []string{"sub#fr"} }},
		{"supported case variant of sub", nil, func(c *oidcprovider.Config) { c.ClaimsSupported = []string{"SUB"} }},
		{"supported case variant of sub, long s", nil, func(c *oidcprovider.Config) { c.ClaimsSupported = []string{"\u017fub"} }},
		{"supported case variant of iss, sharp s", nil, func(c *oidcprovider.Config) { c.ClaimsSupported = []string{"i\u00df"} }},
		{"supported case variant of auth_time", nil, func(c *oidcprovider.Config) { c.ClaimsSupported = []string{"authTime"} }},
		{"supported case variant of email", nil, func(c *oidcprovider.Config) { c.ClaimsSupported = []string{"Email"} }},
		{"supported case variant of roles", nil, func(c *oidcprovider.Config) { c.ClaimsSupported = []string{"ROLES"} }},
		{"supported case variants of each other", nil, func(c *oidcprovider.Config) { c.ClaimsSupported = []string{"tenant", "Tenant"} }},
		{"supported delimiter variants of each other", nil, func(c *oidcprovider.Config) { c.ClaimsSupported = []string{"tenant_id", "tenant-id"} }},
		{"supported tagged case variants", nil, func(c *oidcprovider.Config) { c.ClaimsSupported = []string{"name#fr", "name#FR"} }},
		{"supported tagged names of variant bases", nil, func(c *oidcprovider.Config) { c.ClaimsSupported = []string{"x#fr", "X#de"} }},
		{"supported separator variants of each other", nil, func(c *oidcprovider.Config) { c.ClaimsSupported = []string{"tenant_id", "tenant.id"} }},
		{"supported separator variant of email_verified", nil, func(c *oidcprovider.Config) { c.ClaimsSupported = []string{"email verified"} }},
		{"supported Unicode separator variant of email_verified", nil, func(c *oidcprovider.Config) {
			c.ClaimsSupported = []string{"email\u2010verified"}
		}},
		{"supported deburred variant of email", nil, func(c *oidcprovider.Config) { c.ClaimsSupported = []string{"\u00e9mail"} }},
		{"supported invisible variants of each other", nil, func(c *oidcprovider.Config) {
			c.ClaimsSupported = []string{"tenant", "ten\u200bant"}
		}},
		{"empty acr value", nil, func(c *oidcprovider.Config) { c.ACRValuesSupported = []string{""} }},
		{"acr value with a space", nil, func(c *oidcprovider.Config) { c.ACRValuesSupported = []string{"loa 1"} }},
		{"extension already set", func(s *oauth2.ServerConfig) { s.Extension = noopExtension{} }, nil},
		{"no authorization_code grant", func(s *oauth2.ServerConfig) {
			s.Grants = []oauth2.Grant{grant.NewClientCredentials(grant.Config{
				Storage: s.Storage, AccessTokens: token.NewOpaque(32), AccessTTL: time.Hour,
			})}
		}, nil},
		{"invalid server configuration", func(s *oauth2.ServerConfig) { s.Storage = nil }, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			scfg, cfg := baseServerConfig(), baseConfig()
			if tc.server != nil {
				tc.server(&scfg)
			}

			if tc.config != nil {
				tc.config(&cfg)
			}

			op, err := oidcprovider.New(scfg, cfg)
			require.Error(t, err)
			assert.Nil(t, op)
		})
	}
}

func TestNewRegistersTheProviderAsTheServerExtension(t *testing.T) {
	t.Parallel()

	op, err := oidcprovider.New(baseServerConfig(), baseConfig())
	require.NoError(t, err)
	require.NotNil(t, op.Server())
	assert.NotNil(t, op.Server().Config().Extension, "the provider is the server's extension")
}

// TestNewKeepsItsOwnCopiesOfTheConfiguration: New validates the
// configuration's slices, then keeps its own copies — a caller changing
// them afterwards changes nothing the discovery document publishes (and
// races nothing).
func TestNewKeepsItsOwnCopiesOfTheConfiguration(t *testing.T) {
	t.Parallel()

	acrs := []string{"urn:example:loa:1"}
	claims := []string{"tenant"}
	e := newEnv(t, withConfig(func(c *oidcprovider.Config) { c.ACRValuesSupported, c.ClaimsSupported = acrs, claims }))

	acrs[0], claims[0] = "not visible ascii é \n", "sub"

	rec := serve(e.op.DiscoveryHandler(), get("/.well-known/openid-configuration"))
	require.Equal(t, http.StatusOK, rec.Code)

	var doc struct {
		ACRValues []string `json:"acr_values_supported"`
		Claims    []string `json:"claims_supported"`
	}

	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &doc))
	assert.Equal(t, []string{"urn:example:loa:1"}, doc.ACRValues)
	assert.Contains(t, doc.Claims, "tenant")
}

func TestPaths(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, issuer, prefix string
		want                 oidcprovider.Paths
	}{
		{"root issuer, default prefix", "https://op.example", "", oidcprovider.Paths{
			Discovery: "/.well-known/openid-configuration", Metadata: "/.well-known/oauth-authorization-server",
			JWKS: "/.well-known/jwks.json", Authorize: "/oauth2/authorize", Token: "/oauth2/token",
			Revoke: "/oauth2/revoke", Introspect: "/oauth2/introspect", UserInfo: "/oauth2/userinfo",
		}},
		{"path issuer", "https://op.example/tenant-a", "", oidcprovider.Paths{
			Discovery: "/tenant-a/.well-known/openid-configuration", Metadata: "/.well-known/oauth-authorization-server/tenant-a",
			JWKS: "/tenant-a/.well-known/jwks.json", Authorize: "/tenant-a/oauth2/authorize", Token: "/tenant-a/oauth2/token",
			Revoke: "/tenant-a/oauth2/revoke", Introspect: "/tenant-a/oauth2/introspect", UserInfo: "/tenant-a/oauth2/userinfo",
		}},
		{"path issuer with a terminating slash", "https://op.example/tenant-a/", "/connect", oidcprovider.Paths{
			Discovery: "/tenant-a/.well-known/openid-configuration", Metadata: "/.well-known/oauth-authorization-server/tenant-a",
			JWKS: "/tenant-a/.well-known/jwks.json", Authorize: "/tenant-a/connect/authorize", Token: "/tenant-a/connect/token",
			Revoke: "/tenant-a/connect/revoke", Introspect: "/tenant-a/connect/introspect", UserInfo: "/tenant-a/connect/userinfo",
		}},
		{"root mount", "https://op.example:8443", "/", oidcprovider.Paths{
			Discovery: "/.well-known/openid-configuration", Metadata: "/.well-known/oauth-authorization-server",
			JWKS: "/.well-known/jwks.json", Authorize: "/authorize", Token: "/token",
			Revoke: "/revoke", Introspect: "/introspect", UserInfo: "/userinfo",
		}},
		{"escaped path", "https://op.example/t%C3%A9nant", "", oidcprovider.Paths{
			Discovery: "/t%C3%A9nant/.well-known/openid-configuration", Metadata: "/.well-known/oauth-authorization-server/t%C3%A9nant",
			JWKS: "/t%C3%A9nant/.well-known/jwks.json", Authorize: "/t%C3%A9nant/oauth2/authorize", Token: "/t%C3%A9nant/oauth2/token",
			Revoke: "/t%C3%A9nant/oauth2/revoke", Introspect: "/t%C3%A9nant/oauth2/introspect", UserInfo: "/t%C3%A9nant/oauth2/userinfo",
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newEnv(t, withRoutePrefix(tc.prefix))

			got, err := e.op.Paths(tc.issuer)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestIssuerValidation pins OIDC Core §2 and Discovery §3: an issuer is an
// https URL with a host and no query, fragment or user info, kept verbatim
// (compared exactly, so its canonical form is required); http only for a
// loopback host, on explicit opt-in, matched exactly.
func TestIssuerValidation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		issuer   string
		loopback bool
		ok       bool
	}{
		{"https://op.example", false, true},
		{"https://op.example/", false, true},
		{"https://op.example:8443/tenant/a", false, true},
		{"http://op.example", false, false},
		{"http://op.example", true, false},
		{"http://localhost:8080", false, false},
		{"http://localhost:8080", true, true},
		{"http://127.0.0.1:1338", true, true},
		{"http://127.9.9.9", true, true},
		{"http://[::1]:8080", true, true},
		{"http://localhost.example", true, false},
		{"http://127.0.0.1.nip.io", true, false},
		{"http://10.0.0.1", true, false},
		{"https://op.example?tenant=a", false, false},
		{"https://op.example/?", false, false},
		{"https://op.example#frag", false, false},
		{"https://op.example/#", false, false},
		{"https://user@op.example", false, false},
		{"https:///no-host", false, false},
		{"HTTPS://op.example", false, false},
		{"https://op.example/a b", false, false},
		{"op.example", false, false},
		{"https://op.example/%zz", false, false},
		{"https:op.example", false, false},
		{"", false, false},
		{"ftp://op.example", false, false},
	}

	for _, tc := range cases {
		t.Run(tc.issuer, func(t *testing.T) {
			t.Parallel()

			e := newEnv(t, withConfig(func(c *oidcprovider.Config) { c.AllowInsecureLoopbackIssuer = tc.loopback }))

			_, err := e.op.Paths(tc.issuer)
			if tc.ok {
				require.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, oidcprovider.ErrInvalidIssuer)
		})
	}
}
