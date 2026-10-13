// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// errClientStoreDown is the failure of a client store backend.
var errClientStoreDown = errors.New("client store: connection refused")

// clientsAnswering is a ClientStore answering every lookup with err — a
// failing backend, or an unknown client reported with an error.
func clientsAnswering(t *testing.T, err error) *oauth2.MockClientStore {
	t.Helper()

	clients := oauth2.NewMockClientStore(t)
	clients.EXPECT().LoadClient(mock.Anything, mock.Anything).Return(nil, err)

	return clients
}

// failingClientsEnv is a boundsEnv whose ClientStore is store.
func failingClientsEnv(t *testing.T, store oauth2.ClientStore, resolver oauth2.IssuerResolver) *boundsEnv {
	t.Helper()

	env := newBoundsEnv(t, 0, resolver, nil)
	cfg := env.srv.Config()
	cfg.ClientStore = store

	srv, err := oauth2.NewServer(cfg)
	require.NoError(t, err)

	env.srv = srv

	return env
}

// requireReportedServerError asserts the one server_error the hook got,
// carrying cause.
func requireReportedServerError(t *testing.T, env *boundsEnv, cause error) {
	t.Helper()

	reported := env.sink.collected()
	require.Len(t, reported, 1)
	assert.Equal(t, oauth2.CodeServerError, oauth2.IsCode(reported[0]))
	assert.ErrorIs(t, reported[0], cause)
}

// TestClientStoreFailureIsAServerError: a ClientStore that fails is an
// outage, not an unknown client — answering invalid_client would tell a
// client its credentials are wrong. /authorize answers a bare 500 (no
// redirect URI can be trusted without the client), /token and /introspect
// a 500 server_error, /revoke a 503 temporarily_unavailable (RFC 7009
// §2.2.1: the client must assume the token still exists, and may retry);
// the failure reaches the hook once.
func TestClientStoreFailureIsAServerError(t *testing.T) {
	t.Parallel()

	t.Run("authorize", func(t *testing.T) {
		t.Parallel()

		env := failingClientsEnv(t, clientsAnswering(t, errClientStoreDown), nil)
		rec := serve(env.authorizeHandler(approve), httptest.NewRequest(http.MethodGet, authorizePath+"?"+boundsQuery().Encode(), nil))

		require.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.Equal(t, "oauth2: server error\n", rec.Body.String())
		assert.Empty(t, rec.Header().Get("Location"))
		requireReportedServerError(t, env, errClientStoreDown)
	})

	requests := map[string]func(path string, form url.Values) *http.Request{
		"client_secret_basic": func(path string, form url.Values) *http.Request {
			return boundsPost(path, strings.NewReader(form.Encode()))
		},
		"client_secret_post": func(path string, form url.Values) *http.Request {
			form.Set("client_id", "machine")
			form.Set("client_secret", "machine-secret")

			return formRequest(path, form, false)
		},
		"none": func(path string, form url.Values) *http.Request {
			form.Set("client_id", "spa")

			return formRequest(path, form, false)
		},
	}

	endpoints := []struct {
		path    string
		form    url.Values
		handler func(*oauth2.Server) http.Handler
		status  int
		body    string
	}{
		{"/oauth2/token", url.Values{"grant_type": {"client_credentials"}}, (*oauth2.Server).TokenHandler,
			http.StatusInternalServerError, `{"error":"server_error","error_description":"internal server error"}`},
		{"/oauth2/introspect", url.Values{"token": {"ghost"}}, (*oauth2.Server).IntrospectHandler,
			http.StatusInternalServerError, `{"error":"server_error","error_description":"internal server error"}`},
		{"/oauth2/revoke", url.Values{"token": {"ghost"}}, (*oauth2.Server).RevokeHandler,
			http.StatusServiceUnavailable, `{"error":"temporarily_unavailable","error_description":"revocation temporarily unavailable"}`},
	}

	for _, ep := range endpoints {
		for method, req := range requests {
			t.Run(ep.path+"/"+method, func(t *testing.T) {
				t.Parallel()

				env := failingClientsEnv(t, clientsAnswering(t, errClientStoreDown), nil)
				form := url.Values{}
				for k, v := range ep.form {
					form[k] = v
				}

				rec := serve(ep.handler(env.srv), req(ep.path, form))
				require.Equal(t, ep.status, rec.Code, rec.Body.String())
				assert.JSONEq(t, ep.body, rec.Body.String())
				requireReportedServerError(t, env, errClientStoreDown)
			})
		}
	}
}

// TestClientStoreInvalidClientMeansUnknown pins the ClientStore contract:
// (nil, nil) — or an error carrying invalid_client — reports an unknown
// client, answered as such.
func TestClientStoreInvalidClientMeansUnknown(t *testing.T) {
	t.Parallel()

	env := failingClientsEnv(t, clientsAnswering(t, oauth2.ErrInvalidClient), nil)

	rec := serve(env.authorizeHandler(approve), httptest.NewRequest(http.MethodGet, authorizePath+"?"+boundsQuery().Encode(), nil))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "oauth2: unknown or invalid client\n", rec.Body.String())

	rec = serve(env.srv.TokenHandler(), boundsPost("/oauth2/token", strings.NewReader("grant_type=client_credentials")))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.JSONEq(t, `{"error":"invalid_client","error_description":"client authentication failed"}`, rec.Body.String())
}

// TestRevokeAnswersUnavailableWhenTheResolverFails: at /revoke, an
// IssuerResolver failure leaves the revocation undone like a store failure:
// 503 temporarily_unavailable (RFC 7009 §2.2.1), reported once.
func TestRevokeAnswersUnavailableWhenTheResolverFails(t *testing.T) {
	t.Parallel()

	env := newBoundsEnv(t, 0, failingIssuer{}, nil)

	rec := serve(env.srv.RevokeHandler(), boundsPost("/oauth2/revoke", strings.NewReader("token=ghost")))
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	assert.Equal(t, []string{oauth2.CodeServerError}, env.sink.codes())
}

// lookupFailingStore fails the token lookups it is told to.
type lookupFailingStore struct {
	*writeCountingStore

	access, refresh error
}

func (s *lookupFailingStore) LookupAccessToken(ctx context.Context, hash string) (*oauth2.AccessToken, error) {
	if s.access != nil {
		return nil, s.access
	}

	return s.writeCountingStore.LookupAccessToken(ctx, hash) //nolint:wrapcheck // test double
}

func (s *lookupFailingStore) LookupRefreshToken(ctx context.Context, hash string) (*oauth2.RefreshToken, error) {
	if s.refresh != nil {
		return nil, s.refresh
	}

	return s.writeCountingStore.LookupRefreshToken(ctx, hash) //nolint:wrapcheck // test double
}

// errTokenStoreDown is the failure of a token store backend.
var errTokenStoreDown = errors.New("token store: connection refused")

// TestIntrospectionReportsStorageFailures: a token lookup that fails — not
// one that merely misses — answers {"active":false} (RFC 7662 §2.1: a server
// unable to determine the state of a token SHOULD answer it is not active)
// and reaches the hook as a server_error; a missing token, or one of a
// revoked family, is no failure.
func TestIntrospectionReportsStorageFailures(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name            string
		access, refresh error
		reported        bool
	}{
		{"access lookup fails", errTokenStoreDown, nil, true},
		{"refresh lookup fails", oauth2.ErrInvalidGrant, errTokenStoreDown, true},
		{"unknown token", nil, nil, false},
		{"revoked family", oauth2.ErrTokenFamilyRevoked, oauth2.ErrTokenFamilyRevoked, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := newBoundsEnv(t, 0, nil, nil)
			cfg := env.srv.Config()
			cfg.Storage = &lookupFailingStore{writeCountingStore: env.store, access: tc.access, refresh: tc.refresh}

			srv, err := oauth2.NewServer(cfg)
			require.NoError(t, err)

			rec := serve(srv.IntrospectHandler(), boundsPost("/oauth2/introspect", strings.NewReader("token=ghost")))
			require.Equal(t, http.StatusOK, rec.Code)
			assert.JSONEq(t, `{"active":false}`, rec.Body.String())

			if !tc.reported {
				assert.Empty(t, env.sink.collected())

				return
			}

			requireReportedServerError(t, env, errTokenStoreDown)
		})
	}
}
