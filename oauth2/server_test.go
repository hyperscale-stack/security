// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"context"
	"encoding/json"
	"errors"
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
	testClientID     = "client-abc"
	testClientSecret = "secret-xyz"
)

// staticClientStore is a tiny in-memory [oauth2.ClientStore].
type staticClientStore struct{ clients map[string]oauth2.Client }

func (s *staticClientStore) LoadClient(_ context.Context, id string) (oauth2.Client, error) {
	c, ok := s.clients[id]
	if !ok {
		return nil, nil
	}

	return c, nil
}

// failingIssuer is an [oauth2.IssuerResolver] that always errors.
type failingIssuer struct{}

func (failingIssuer) Resolve(context.Context, *http.Request) (string, string, error) {
	return "", "", errors.New("issuer backend down")
}

// legacyGrant registers a grant_type without a real implementation — enough
// for the profile-constraint check at NewServer time.
type legacyGrant struct{ typ string }

func (g legacyGrant) Type() string { return g.typ }
func (g legacyGrant) Handle(context.Context, oauth2.GrantRequest) (*oauth2.GrantResponse, error) {
	return nil, oauth2.ErrServerError
}

func newTestServer(t *testing.T) (*oauth2.Server, *memory.Store) {
	t.Helper()

	store := memory.New()
	clients := &staticClientStore{clients: map[string]oauth2.Client{
		testClientID: &oauth2.DefaultClient{
			IDValue:     testClientID,
			Secret:      testClientSecret,
			TypeValue:   oauth2.ClientConfidential,
			ScopeValues: []string{"api:read"},
		},
	}}

	cfg := grant.Config{
		Storage:             store,
		AccessTokens:        token.NewOpaque(32),
		RefreshTokens:       token.OpaqueRefreshAdapter{Opaque: token.NewOpaque(32)},
		AccessTTL:           time.Hour,
		RefreshTTL:          24 * time.Hour,
		RotateRefreshTokens: true,
	}

	srv, err := oauth2.NewServer(oauth2.ServerConfig{
		Profile:        oauth2.Profile20BCP,
		Storage:        store,
		ClientStore:    clients,
		IssuerResolver: oauth2.StaticIssuer("https://auth.example", "api"),
		Grants:         []oauth2.Grant{grant.NewClientCredentials(cfg), grant.NewRefreshToken(cfg)},
		ClientAuth:     []oauth2.ClientAuthenticator{clientauth.NewBasic(), clientauth.NewPost()},
	})
	require.NoError(t, err)

	return srv, store
}

// formRequest builds a POST x-www-form-urlencoded request with Basic auth.
func formRequest(path string, form url.Values, withAuth bool) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if withAuth {
		req.SetBasicAuth(testClientID, testClientSecret)
	}

	return req
}

func TestNewServerValidation(t *testing.T) {
	t.Parallel()

	store := memory.New()
	clients := &staticClientStore{}
	iss := oauth2.StaticIssuer("https://auth.example", "api")
	auth := []oauth2.ClientAuthenticator{clientauth.NewBasic()}

	cases := []struct {
		name string
		cfg  oauth2.ServerConfig
	}{
		{"missing storage", oauth2.ServerConfig{ClientStore: clients, IssuerResolver: iss, ClientAuth: auth}},
		{"missing client store", oauth2.ServerConfig{Storage: store, IssuerResolver: iss, ClientAuth: auth}},
		{"missing issuer", oauth2.ServerConfig{Storage: store, ClientStore: clients, ClientAuth: auth}},
		{"missing client auth", oauth2.ServerConfig{Storage: store, ClientStore: clients, IssuerResolver: iss}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := oauth2.NewServer(tc.cfg)
			require.Error(t, err)
		})
	}
}

func TestNewServerDuplicateGrantType(t *testing.T) {
	t.Parallel()

	_, err := oauth2.NewServer(oauth2.ServerConfig{
		Storage:        memory.New(),
		ClientStore:    &staticClientStore{},
		IssuerResolver: oauth2.StaticIssuer("https://auth.example", "api"),
		ClientAuth:     []oauth2.ClientAuthenticator{clientauth.NewBasic()},
		Grants:         []oauth2.Grant{legacyGrant{typ: "client_credentials"}, legacyGrant{typ: "client_credentials"}},
		Profile:        oauth2.Profile20,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate grant type")
}

func TestNewServerProfileConstraints(t *testing.T) {
	t.Parallel()

	base := oauth2.ServerConfig{
		Storage:        memory.New(),
		ClientStore:    &staticClientStore{},
		IssuerResolver: oauth2.StaticIssuer("https://auth.example", "api"),
		ClientAuth:     []oauth2.ClientAuthenticator{clientauth.NewBasic()},
	}

	// BCP refuses the legacy password / implicit grants.
	for _, legacy := range []string{"password", "implicit"} {
		cfg := base
		cfg.Profile = oauth2.Profile20BCP
		cfg.Grants = []oauth2.Grant{legacyGrant{typ: legacy}}

		_, err := oauth2.NewServer(cfg)
		require.Error(t, err, legacy)
		assert.Contains(t, err.Error(), legacy)
	}

	// Profile20 allows them.
	cfg := base
	cfg.Profile = oauth2.Profile20
	cfg.Grants = []oauth2.Grant{legacyGrant{typ: "password"}}

	_, err := oauth2.NewServer(cfg)
	require.NoError(t, err)
}

func TestServerConfigDefaultsClock(t *testing.T) {
	t.Parallel()

	srv, _ := newTestServer(t)
	assert.NotNil(t, srv.Config().Now, "NewServer defaults Now to time.Now")
}

func TestTokenEndpoint(t *testing.T) {
	t.Parallel()

	t.Run("GET is rejected", func(t *testing.T) {
		t.Parallel()

		srv, _ := newTestServer(t)
		rec := httptest.NewRecorder()
		srv.TokenHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth2/token", nil))
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("missing client auth is 401", func(t *testing.T) {
		t.Parallel()

		srv, _ := newTestServer(t)
		rec := httptest.NewRecorder()
		srv.TokenHandler().ServeHTTP(rec,
			formRequest("/oauth2/token", url.Values{"grant_type": {"client_credentials"}}, false))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("missing grant_type is 400 invalid_request", func(t *testing.T) {
		t.Parallel()

		srv, _ := newTestServer(t)
		rec := httptest.NewRecorder()
		srv.TokenHandler().ServeHTTP(rec, formRequest("/oauth2/token", url.Values{}, true))
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, oauth2.CodeInvalidRequest, decodeError(t, rec))
	})

	t.Run("unsupported grant_type is 400", func(t *testing.T) {
		t.Parallel()

		srv, _ := newTestServer(t)
		rec := httptest.NewRecorder()
		srv.TokenHandler().ServeHTTP(rec,
			formRequest("/oauth2/token", url.Values{"grant_type": {"password"}}, true))
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, oauth2.CodeUnsupportedGrantType, decodeError(t, rec))
	})

	t.Run("client_credentials success", func(t *testing.T) {
		t.Parallel()

		srv, _ := newTestServer(t)
		rec := httptest.NewRecorder()
		srv.TokenHandler().ServeHTTP(rec, formRequest("/oauth2/token",
			url.Values{"grant_type": {"client_credentials"}, "scope": {"api:read"}}, true))

		require.Equal(t, http.StatusOK, rec.Code)

		var body map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.NotEmpty(t, body["access_token"])
		assert.Equal(t, "Bearer", body["token_type"])
	})
}

func TestTokenEndpointIssuerError(t *testing.T) {
	t.Parallel()

	store := memory.New()
	cfg := grant.Config{
		Storage:      store,
		AccessTokens: token.NewOpaque(32),
		AccessTTL:    time.Hour,
	}

	srv, err := oauth2.NewServer(oauth2.ServerConfig{
		Storage:     store,
		ClientStore: &staticClientStore{clients: map[string]oauth2.Client{
			testClientID: &oauth2.DefaultClient{IDValue: testClientID, Secret: testClientSecret},
		}},
		IssuerResolver: failingIssuer{},
		Grants:         []oauth2.Grant{grant.NewClientCredentials(cfg)},
		ClientAuth:     []oauth2.ClientAuthenticator{clientauth.NewBasic()},
	})
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	srv.TokenHandler().ServeHTTP(rec,
		formRequest("/oauth2/token", url.Values{"grant_type": {"client_credentials"}}, true))

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, oauth2.CodeServerError, decodeError(t, rec))
}

func TestRevokeEndpoint(t *testing.T) {
	t.Parallel()

	t.Run("GET is rejected", func(t *testing.T) {
		t.Parallel()

		srv, _ := newTestServer(t)
		rec := httptest.NewRecorder()
		srv.RevokeHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth2/revoke", nil))
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("missing token is 400", func(t *testing.T) {
		t.Parallel()

		srv, _ := newTestServer(t)
		rec := httptest.NewRecorder()
		srv.RevokeHandler().ServeHTTP(rec, formRequest("/oauth2/revoke", url.Values{}, true))
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("unknown token still returns 200", func(t *testing.T) {
		t.Parallel()

		srv, _ := newTestServer(t)
		rec := httptest.NewRecorder()
		srv.RevokeHandler().ServeHTTP(rec,
			formRequest("/oauth2/revoke", url.Values{"token": {"nope"}}, true))
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("revokes a stored access token of the family", func(t *testing.T) {
		t.Parallel()

		srv, store := newTestServer(t)
		ctx := context.Background()
		require.NoError(t, store.SaveAccessToken(ctx, &oauth2.AccessToken{
			TokenHash: oauth2.HashToken(nil, "raw-access"),
			ClientID:  testClientID,
			FamilyID:  "fam-1",
			ExpiresAt: time.Now().Add(time.Hour),
		}))

		rec := httptest.NewRecorder()
		srv.RevokeHandler().ServeHTTP(rec,
			formRequest("/oauth2/revoke", url.Values{"token": {"raw-access"}}, true))
		assert.Equal(t, http.StatusOK, rec.Code)

		_, err := store.LookupAccessToken(ctx, oauth2.HashToken(nil, "raw-access"))
		assert.Error(t, err, "access token must be revoked")
	})

	t.Run("revokes a stored refresh token family", func(t *testing.T) {
		t.Parallel()

		srv, store := newTestServer(t)
		ctx := context.Background()
		require.NoError(t, store.SaveRefreshToken(ctx, &oauth2.RefreshToken{
			TokenHash: oauth2.HashToken(nil, "raw-refresh"),
			ClientID:  testClientID,
			FamilyID:  "fam-2",
			ExpiresAt: time.Now().Add(time.Hour),
		}))

		rec := httptest.NewRecorder()
		srv.RevokeHandler().ServeHTTP(rec,
			formRequest("/oauth2/revoke", url.Values{"token": {"raw-refresh"}}, true))
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

func TestIntrospectEndpoint(t *testing.T) {
	t.Parallel()

	t.Run("GET is rejected", func(t *testing.T) {
		t.Parallel()

		srv, _ := newTestServer(t)
		rec := httptest.NewRecorder()
		srv.IntrospectHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth2/introspect", nil))
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("missing token is 400", func(t *testing.T) {
		t.Parallel()

		srv, _ := newTestServer(t)
		rec := httptest.NewRecorder()
		srv.IntrospectHandler().ServeHTTP(rec, formRequest("/oauth2/introspect", url.Values{}, true))
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("unknown token is inactive", func(t *testing.T) {
		t.Parallel()

		srv, _ := newTestServer(t)
		assert.False(t, introspect(t, srv, "ghost")["active"].(bool))
	})

	t.Run("active access token is active", func(t *testing.T) {
		t.Parallel()

		srv, store := newTestServer(t)
		require.NoError(t, store.SaveAccessToken(context.Background(), &oauth2.AccessToken{
			TokenHash: oauth2.HashToken(nil, "live-at"),
			ClientID:  testClientID,
			Subject:   "user-1",
			Scope:     "api:read",
			IssuedAt:  time.Now().Add(-time.Minute),
			ExpiresAt: time.Now().Add(time.Hour),
		}))

		body := introspect(t, srv, "live-at")
		assert.True(t, body["active"].(bool))
		assert.Equal(t, "Bearer", body["token_type"])
		assert.Equal(t, "user-1", body["sub"])
	})

	t.Run("expired access token is inactive", func(t *testing.T) {
		t.Parallel()

		srv, store := newTestServer(t)
		require.NoError(t, store.SaveAccessToken(context.Background(), &oauth2.AccessToken{
			TokenHash: oauth2.HashToken(nil, "dead-at"),
			ClientID:  testClientID,
			ExpiresAt: time.Now().Add(-time.Hour),
		}))
		assert.False(t, introspect(t, srv, "dead-at")["active"].(bool))
	})

	t.Run("active refresh token is active", func(t *testing.T) {
		t.Parallel()

		srv, store := newTestServer(t)
		require.NoError(t, store.SaveRefreshToken(context.Background(), &oauth2.RefreshToken{
			TokenHash: oauth2.HashToken(nil, "live-rt"),
			ClientID:  testClientID,
			ExpiresAt: time.Now().Add(time.Hour),
		}))

		body := introspect(t, srv, "live-rt")
		assert.True(t, body["active"].(bool))
		assert.Equal(t, "refresh_token", body["token_type"])
	})

	t.Run("consumed refresh token is inactive", func(t *testing.T) {
		t.Parallel()

		srv, store := newTestServer(t)
		require.NoError(t, store.SaveRefreshToken(context.Background(), &oauth2.RefreshToken{
			TokenHash: oauth2.HashToken(nil, "used-rt"),
			ClientID:  testClientID,
			ExpiresAt: time.Now().Add(time.Hour),
			Consumed:  true,
		}))
		assert.False(t, introspect(t, srv, "used-rt")["active"].(bool))
	})
}

func TestMetadataEndpoint(t *testing.T) {
	t.Parallel()

	t.Run("advertises configuration", func(t *testing.T) {
		t.Parallel()

		srv, _ := newTestServer(t)
		rec := httptest.NewRecorder()
		srv.MetadataHandler().ServeHTTP(rec,
			httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))

		require.Equal(t, http.StatusOK, rec.Code)

		var body map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, "https://auth.example", body["issuer"])
		assert.Equal(t, "https://auth.example/oauth2/token", body["token_endpoint"])
		assert.Equal(t, []any{"S256"}, body["code_challenge_methods_supported"])
	})

	t.Run("issuer error is 500", func(t *testing.T) {
		t.Parallel()

		store := memory.New()
		srv, err := oauth2.NewServer(oauth2.ServerConfig{
			Storage:        store,
			ClientStore:    &staticClientStore{},
			IssuerResolver: failingIssuer{},
			ClientAuth:     []oauth2.ClientAuthenticator{clientauth.NewBasic()},
		})
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		srv.MetadataHandler().ServeHTTP(rec,
			httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}

// decodeError extracts the "error" field of an RFC 6749 §5.2 envelope.
func decodeError(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))

	code, _ := body["error"].(string)

	return code
}

// introspect POSTs token to /introspect and returns the decoded body.
func introspect(t *testing.T, srv *oauth2.Server, raw string) map[string]any {
	t.Helper()

	rec := httptest.NewRecorder()
	srv.IntrospectHandler().ServeHTTP(rec,
		formRequest("/oauth2/introspect", url.Values{"token": {raw}}, true))
	require.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))

	return body
}

func TestMetadataRoutePrefix(t *testing.T) {
	t.Parallel()

	const issuer = "https://auth.example"

	build := func(t *testing.T, prefix string) *oauth2.Server {
		t.Helper()

		srv, err := oauth2.NewServer(oauth2.ServerConfig{
			Storage:        memory.New(),
			ClientStore:    &staticClientStore{},
			IssuerResolver: oauth2.StaticIssuer(issuer, "api"),
			ClientAuth:     []oauth2.ClientAuthenticator{clientauth.NewBasic()},
			RoutePrefix:    prefix,
		})
		require.NoError(t, err)

		return srv
	}

	doc := func(t *testing.T, srv *oauth2.Server) map[string]any {
		t.Helper()

		rec := httptest.NewRecorder()
		srv.MetadataHandler().ServeHTTP(rec,
			httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))
		require.Equal(t, http.StatusOK, rec.Code)

		var body map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))

		return body
	}

	cases := []struct {
		name   string
		prefix string
		want   string // normalized prefix
	}{
		{"default", "", "/oauth2"},
		{"custom", "/auth", "/auth"},
		{"missing leading slash", "auth", "/auth"},
		{"trailing slash", "/auth/", "/auth"},
		{"root mount", "/", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := build(t, tc.prefix)

			// The normalized prefix is what the config reports back.
			assert.Equal(t, tc.want, srv.Config().RoutePrefix)

			body := doc(t, srv)
			routes := issuer + tc.want

			assert.Equal(t, routes+"/token", body["token_endpoint"])
			assert.Equal(t, routes+"/revoke", body["revocation_endpoint"])
			assert.Equal(t, routes+"/introspect", body["introspection_endpoint"])
			assert.Equal(t, routes+"/authorize", body["authorization_endpoint"])

			// jwks_uri keeps the host-root .well-known location regardless.
			assert.Equal(t, issuer+"/.well-known/jwks.json", body["jwks_uri"])
		})
	}
}

// passwordVerifier is a ResourceOwnerVerifier accepting a single account.
type passwordVerifier struct{}

func (passwordVerifier) VerifyResourceOwner(_ context.Context, username, password string) (string, error) {
	if username == "alice" && password == "s3cr3t" {
		return "alice", nil
	}

	return "", errors.New("invalid credentials")
}

// TestTokenEndpointLegacyPasswordGrant wires the opt-in legacy password
// grant under Profile20 and exercises it end-to-end through /token.
func TestTokenEndpointLegacyPasswordGrant(t *testing.T) {
	t.Parallel()

	store := memory.New()
	cfg := grant.Config{
		Storage: store, AccessTokens: token.NewOpaque(32), AccessTTL: time.Hour,
	}

	srv, err := oauth2.NewServer(oauth2.ServerConfig{
		Profile: oauth2.Profile20, // legacy grants are accepted only here
		Storage: store,
		ClientStore: &staticClientStore{clients: map[string]oauth2.Client{
			testClientID: &oauth2.DefaultClient{
				IDValue: testClientID, Secret: testClientSecret, TypeValue: oauth2.ClientConfidential,
			},
		}},
		IssuerResolver: oauth2.StaticIssuer("https://auth.example", "api"),
		Grants:         []oauth2.Grant{grant.NewLegacyPassword(cfg, passwordVerifier{})},
		ClientAuth:     []oauth2.ClientAuthenticator{clientauth.NewBasic()},
	})
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	srv.TokenHandler().ServeHTTP(rec, formRequest("/oauth2/token",
		url.Values{"grant_type": {"password"}, "username": {"alice"}, "password": {"s3cr3t"}}, true))

	require.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.NotEmpty(t, body["access_token"])
	assert.Equal(t, "Bearer", body["token_type"])
}

// TestNewServerRefusesLegacyPasswordOutsideProfile20 confirms the opt-in
// legacy grant is rejected at construction under the BCP / 2.1 profiles.
func TestNewServerRefusesLegacyPasswordOutsideProfile20(t *testing.T) {
	t.Parallel()

	store := memory.New()
	cfg := grant.Config{
		Storage: store, AccessTokens: token.NewOpaque(32), AccessTTL: time.Hour,
	}

	for _, profile := range []oauth2.Profile{oauth2.Profile20BCP, oauth2.Profile21Draft} {
		_, err := oauth2.NewServer(oauth2.ServerConfig{
			Profile:        profile,
			Storage:        store,
			ClientStore:    &staticClientStore{},
			IssuerResolver: oauth2.StaticIssuer("https://auth.example", "api"),
			Grants:         []oauth2.Grant{grant.NewLegacyPassword(cfg, passwordVerifier{})},
			ClientAuth:     []oauth2.ClientAuthenticator{clientauth.NewBasic()},
		})
		require.Error(t, err, profile)
		assert.Contains(t, err.Error(), "password")
	}
}
