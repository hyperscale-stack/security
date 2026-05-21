// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package integrations holds end-to-end tests that wire the whole stack
// (transport adapters + grants + storage) together. They are NOT part of
// the public API; they live behind an internal/ boundary so external
// consumers cannot import them.
package integrations_test

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

const (
	clientID     = "5cc06c3b-5755-4229-958c-a515a245aaeb"
	clientSecret = "WTvuAztPD2XBauomleRzGFYuZawS07Ym"
)

// staticClientStore is a tiny [oauth2.ClientStore] used by the integration
// tests. Mirrors the in-memory store used by the legacy MVP.
type staticClientStore struct{ clients map[string]oauth2.Client }

func (s *staticClientStore) LoadClient(_ context.Context, id string) (oauth2.Client, error) {
	c, ok := s.clients[id]
	if !ok {
		return nil, nil
	}

	return c, nil
}

func newServer(t *testing.T) (*oauth2.Server, *memory.Store) {
	t.Helper()

	store := memory.New()
	client := &oauth2.DefaultClient{
		IDValue:           clientID,
		Secret:            clientSecret,
		TypeValue:         oauth2.ClientConfidential,
		RedirectURIValues: []string{"https://connect.myservice.tld"},
		ScopeValues:       []string{"api:read"},
	}
	clients := &staticClientStore{clients: map[string]oauth2.Client{clientID: client}}

	cfg := grant.Config{
		Storage:       store,
		AccessTokens:  token.NewOpaque(32),
		RefreshTokens: token.OpaqueRefreshAdapter{Opaque: token.NewOpaque(32)},
		AccessTTL:     time.Hour,
		RefreshTTL:    24 * time.Hour,
		RotateRefreshTokens: true,
	}

	srv, err := oauth2.NewServer(oauth2.ServerConfig{
		Profile:        oauth2.Profile20BCP,
		Storage:        store,
		ClientStore:    clients,
		IssuerResolver: oauth2.StaticIssuer("https://auth.example", "api"),
		Grants:         []oauth2.Grant{grant.NewClientCredentials(cfg), grant.NewRefreshToken(cfg)},
		ClientAuth: []oauth2.ClientAuthenticator{
			clientauth.NewBasic(),
			clientauth.NewPost(),
		},
	})
	require.NoError(t, err)

	return srv, store
}

// TestOAuth2ClientCredentialsViaTokenEndpoint is the modern equivalent of
// the legacy TestOauth2AuthByClient: a confidential client authenticates
// over HTTP Basic and obtains an access token from /token.
func TestOAuth2ClientCredentialsViaTokenEndpoint(t *testing.T) {
	t.Parallel()

	srv, _ := newServer(t)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", "api:read")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	rec := httptest.NewRecorder()
	srv.TokenHandler().ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.NotEmpty(t, body["access_token"], "must mint an access token")
	assert.Equal(t, "Bearer", body["token_type"])
	assert.Equal(t, "api:read", body["scope"])
	_, hasRefresh := body["refresh_token"]
	assert.False(t, hasRefresh, "client_credentials MUST NOT issue refresh tokens (RFC 6749 §4.4.3)")
}

// TestOAuth2ClientCredentialsBadSecret is the modern equivalent of the
// legacy TestOauth2AuthByClientWithBadPassword: wrong secret returns
// 401 invalid_client with WWW-Authenticate.
func TestOAuth2ClientCredentialsBadSecret(t *testing.T) {
	t.Parallel()

	srv, _ := newServer(t)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, "wrong-secret")

	rec := httptest.NewRecorder()
	srv.TokenHandler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "Basic")

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, oauth2.CodeInvalidClient, body["error"])
}

// TestOAuth2ClientCredentialsUnknownClient is the modern equivalent of the
// legacy TestOauth2AuthByClientWithBadClientID.
func TestOAuth2ClientCredentialsUnknownClient(t *testing.T) {
	t.Parallel()

	srv, _ := newServer(t)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("unknown-client", "whatever")

	rec := httptest.NewRecorder()
	srv.TokenHandler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestOAuth2ClientCredentialsNoAuthHeader is the modern equivalent of the
// legacy TestOauth2AuthByClientWithNoAuthHeader: no client credentials
// returns 401 invalid_client.
func TestOAuth2ClientCredentialsNoAuthHeader(t *testing.T) {
	t.Parallel()

	srv, _ := newServer(t)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	srv.TokenHandler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}
