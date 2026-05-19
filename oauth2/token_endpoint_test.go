// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

// memClientStore is a tiny in-memory ClientStore for the endpoint tests.
type memClientStore struct{ clients map[string]oauth2.Client }

func (s *memClientStore) LoadClient(_ context.Context, id string) (oauth2.Client, error) {
	c, ok := s.clients[id]
	if !ok {
		return nil, nil
	}

	return c, nil
}

func newClient(id, secret string) oauth2.Client {
	return &oauth2.DefaultClient{
		IDValue:           id,
		Secret:            secret,
		TypeValue:         oauth2.ClientConfidential,
		RedirectURIValues: []string{"https://app.example/cb"},
		ScopeValues:       []string{"read:mail"},
	}
}

func newServer(t *testing.T) (*oauth2.Server, *memory.Store, oauth2.Client) {
	t.Helper()

	store := memory.New()
	c := newClient("client-1", "secret-1")
	clients := &memClientStore{clients: map[string]oauth2.Client{c.ID(): c}}

	cfg := grant.Config{
		Storage: store, AccessTokens: token.NewOpaque([]byte("pep"), 32),
		RefreshTokens: token.OpaqueRefreshAdapter{Opaque: token.NewOpaque([]byte("pep"), 32)},
		AccessTTL:     time.Hour, RefreshTTL: 24 * time.Hour, RotateRefreshTokens: true,
	}

	srv, err := oauth2.NewServer(oauth2.ServerConfig{
		Profile:        oauth2.Profile20BCP,
		Storage:        store,
		ClientStore:    clients,
		IssuerResolver: oauth2.StaticIssuer("https://auth.example", "api"),
		Grants: []oauth2.Grant{
			grant.NewClientCredentials(cfg),
			grant.NewRefreshToken(cfg),
		},
		ClientAuth: []oauth2.ClientAuthenticator{clientauth.NewBasic(), clientauth.NewPost()},
	})
	require.NoError(t, err)

	return srv, store, c
}

func clientCredsRequest(c oauth2.Client) *http.Request {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", "read:mail")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.ID(), c.(*oauth2.DefaultClient).Secret)

	return req
}

func TestTokenEndpointClientCredentialsSuccess(t *testing.T) {
	t.Parallel()

	srv, _, c := newServer(t)
	rec := httptest.NewRecorder()
	srv.TokenHandler().ServeHTTP(rec, clientCredsRequest(c))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.NotEmpty(t, body["access_token"])
	assert.Equal(t, "Bearer", body["token_type"])
	assert.Equal(t, "read:mail", body["scope"])
	_, hasRefresh := body["refresh_token"]
	assert.False(t, hasRefresh, "client_credentials MUST NOT issue refresh tokens")
}

func TestTokenEndpointMissingGrantType(t *testing.T) {
	t.Parallel()

	srv, _, c := newServer(t)
	form := url.Values{}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.ID(), c.(*oauth2.DefaultClient).Secret)

	rec := httptest.NewRecorder()
	srv.TokenHandler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, oauth2.CodeInvalidRequest, body["error"])
}

func TestTokenEndpointInvalidClient(t *testing.T) {
	t.Parallel()

	srv, _, _ := newServer(t)
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("client-1", "wrong-secret")

	rec := httptest.NewRecorder()
	srv.TokenHandler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "Basic")
}

func TestTokenEndpointUnsupportedGrantType(t *testing.T) {
	t.Parallel()

	srv, _, c := newServer(t)
	form := url.Values{}
	form.Set("grant_type", "password")
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.ID(), c.(*oauth2.DefaultClient).Secret)

	rec := httptest.NewRecorder()
	srv.TokenHandler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, oauth2.CodeUnsupportedGrantType, body["error"])
}

func TestMetadataEndpointAdvertisesConfig(t *testing.T) {
	t.Parallel()

	srv, _, _ := newServer(t)
	rec := httptest.NewRecorder()
	srv.MetadataHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))

	assert.Equal(t, http.StatusOK, rec.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "https://auth.example", body["issuer"])
	grants := body["grant_types_supported"].([]any)
	assert.Len(t, grants, 2)
	methods := body["token_endpoint_auth_methods_supported"].([]any)
	assert.Contains(t, methods, "client_secret_basic")
}

func TestProfileBCPRefusesPasswordGrantAtBoot(t *testing.T) {
	t.Parallel()

	store := memory.New()
	clients := &memClientStore{clients: map[string]oauth2.Client{"c": newClient("c", "s")}}

	_, err := oauth2.NewServer(oauth2.ServerConfig{
		Profile:        oauth2.Profile20BCP,
		Storage:        store,
		ClientStore:    clients,
		IssuerResolver: oauth2.StaticIssuer("https://auth.example", "api"),
		Grants:         []oauth2.Grant{stubGrant{t: "password"}},
		ClientAuth:     []oauth2.ClientAuthenticator{clientauth.NewBasic()},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "password")
}

// stubGrant lets the profile test register a "password" grant without
// pulling in legacy implementation code.
type stubGrant struct{ t string }

func (g stubGrant) Type() string { return g.t }
func (g stubGrant) Handle(context.Context, oauth2.GrantRequest) (*oauth2.GrantResponse, error) {
	return nil, oauth2.ErrServerError
}
