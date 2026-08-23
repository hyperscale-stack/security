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
	"sync"
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

// errorSink records everything the [oauth2.ErrorHook] is handed.
type errorSink struct {
	mu   sync.Mutex
	errs []error
}

func (s *errorSink) hook(_ context.Context, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.errs = append(s.errs, err)
}

func (s *errorSink) collected() []error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]error(nil), s.errs...)
}

func (s *errorSink) codes() []string {
	out := make([]string, 0, len(s.errs))
	for _, err := range s.collected() {
		out = append(out, oauth2.IsCode(err))
	}

	return out
}

// revokeFailingStore fails the revocation paths so the swallowed errors
// have something to be observed by.
type revokeFailingStore struct {
	*memory.Store

	err error
}

func (s *revokeFailingStore) RevokeAccessToken(context.Context, string) error { return s.err }

func (s *revokeFailingStore) RevokeRefreshFamily(context.Context, string) error { return s.err }

// hookServerConfig is the baseline config shared by the error-hook tests:
// memory storage, one confidential client, Basic client authentication.
func hookServerConfig(store oauth2.Storage) oauth2.ServerConfig {
	cfg := grant.Config{
		Storage:             store,
		AccessTokens:        token.NewOpaque(32),
		RefreshTokens:       token.OpaqueRefreshAdapter{Opaque: token.NewOpaque(32)},
		AccessTTL:           time.Hour,
		RefreshTTL:          24 * time.Hour,
		RotateRefreshTokens: true,
	}

	return oauth2.ServerConfig{
		Profile: oauth2.Profile20BCP,
		Storage: store,
		ClientStore: &staticClientStore{clients: map[string]oauth2.Client{
			testClientID: &oauth2.DefaultClient{
				IDValue:           testClientID,
				Secret:            testClientSecret,
				TypeValue:         oauth2.ClientConfidential,
				RedirectURIValues: []string{redirectURI},
				ScopeValues:       []string{"api:read"},
			},
		}},
		IssuerResolver: oauth2.StaticIssuer("https://auth.example", "api"),
		Grants:         []oauth2.Grant{grant.NewClientCredentials(cfg), grant.NewRefreshToken(cfg)},
		ClientAuth:     []oauth2.ClientAuthenticator{clientauth.NewBasic()},
	}
}

func TestOnErrorReportsServerErrorCause(t *testing.T) {
	t.Parallel()

	sink := &errorSink{}
	cfg := hookServerConfig(memory.New())
	cfg.IssuerResolver = failingIssuer{}
	cfg.OnError = sink.hook

	srv, err := oauth2.NewServer(cfg)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	srv.TokenHandler().ServeHTTP(rec, formRequest("/token",
		url.Values{"grant_type": {"client_credentials"}}, true))

	// The wire body stays cause-free...
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NotContains(t, rec.Body.String(), "issuer backend down")

	// ...but the hook sees the whole envelope, cause included.
	got := sink.collected()
	require.Len(t, got, 1)
	assert.Equal(t, oauth2.CodeServerError, oauth2.IsCode(got[0]))
	assert.ErrorContains(t, got[0], "oauth2: server_error")
	assert.ErrorContains(t, errors.Unwrap(got[0]), "issuer backend down")
}

func TestOnErrorReportsClientErrors(t *testing.T) {
	t.Parallel()

	sink := &errorSink{}
	cfg := hookServerConfig(memory.New())
	cfg.OnError = sink.hook

	srv, err := oauth2.NewServer(cfg)
	require.NoError(t, err)

	cases := []struct {
		name    string
		handler http.Handler
		req     *http.Request
		want    string
	}{
		{
			"token: wrong method",
			srv.TokenHandler(),
			httptest.NewRequest(http.MethodGet, "/token", nil),
			oauth2.CodeInvalidRequest,
		},
		{
			"token: unknown grant_type",
			srv.TokenHandler(),
			formRequest("/token", url.Values{"grant_type": {"nope"}}, true),
			oauth2.CodeUnsupportedGrantType,
		},
		{
			"token: unauthenticated client",
			srv.TokenHandler(),
			formRequest("/token", url.Values{"grant_type": {"client_credentials"}}, false),
			oauth2.CodeInvalidClient,
		},
		{
			"revoke: missing token",
			srv.RevokeHandler(),
			formRequest("/revoke", url.Values{}, true),
			oauth2.CodeInvalidRequest,
		},
		{
			"introspect: missing token",
			srv.IntrospectHandler(),
			formRequest("/introspect", url.Values{}, true),
			oauth2.CodeInvalidRequest,
		},
	}

	for _, tc := range cases {
		tc.handler.ServeHTTP(httptest.NewRecorder(), tc.req)
	}

	want := make([]string, 0, len(cases))
	for _, tc := range cases {
		want = append(want, tc.want)
	}

	assert.Equal(t, want, sink.codes())
}

func TestOnErrorIsOptional(t *testing.T) {
	t.Parallel()

	cfg := hookServerConfig(memory.New())
	cfg.IssuerResolver = failingIssuer{}

	srv, err := oauth2.NewServer(cfg)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	// No hook configured: the server must behave exactly as before.
	assert.NotPanics(t, func() {
		srv.TokenHandler().ServeHTTP(rec, formRequest("/token",
			url.Values{"grant_type": {"client_credentials"}}, true))
	})
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestOnErrorReportsAuthorizeErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		query url.Values
		want  string
	}{
		{
			// Refused before the redirect URI is trusted: answered with a
			// bare 400, so the hook is the only trace.
			name: "unknown client",
			query: url.Values{
				"response_type": {"code"},
				"client_id":     {"ghost"},
				"redirect_uri":  {redirectURI},
			},
			want: oauth2.CodeInvalidClient,
		},
		{
			name: "unregistered redirect_uri",
			query: url.Values{
				"response_type": {"code"},
				"client_id":     {testClientID},
				"redirect_uri":  {"https://evil.example/cb"},
			},
			want: oauth2.CodeInvalidRequest,
		},
		{
			// Redirected back to the client: the code travels, nothing else.
			name: "unsupported response_type",
			query: url.Values{
				"response_type": {"magic"},
				"client_id":     {testClientID},
				"redirect_uri":  {redirectURI},
			},
			want: oauth2.CodeUnsupportedResponseType,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sink := &errorSink{}
			cfg := hookServerConfig(memory.New())
			cfg.OnError = sink.hook

			srv, err := oauth2.NewServer(cfg)
			require.NoError(t, err)

			handler := srv.AuthorizeHandler(oauth2.AuthorizeConfig{},
				func(http.ResponseWriter, *http.Request, *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
					return &oauth2.Consent{Approved: true, Subject: "alice"}, nil
				})

			handler.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequest(http.MethodGet, "/authorize?"+tc.query.Encode(), nil))

			assert.Equal(t, []string{tc.want}, sink.codes())
		})
	}
}

func TestOnErrorReportsFailedRevocation(t *testing.T) {
	t.Parallel()

	sink := &errorSink{}
	store := &revokeFailingStore{Store: memory.New(), err: errors.New("revocation backend down")}
	cfg := hookServerConfig(store)
	cfg.OnError = sink.hook

	srv, err := oauth2.NewServer(cfg)
	require.NoError(t, err)

	// Mint a token pair to revoke.
	rec := httptest.NewRecorder()
	srv.TokenHandler().ServeHTTP(rec, formRequest("/token",
		url.Values{"grant_type": {"client_credentials"}}, true))
	require.Equal(t, http.StatusOK, rec.Code)

	var issued struct {
		AccessToken string `json:"access_token"`
	}

	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &issued))
	require.NotEmpty(t, issued.AccessToken)
	require.Empty(t, sink.codes(), "a successful /token must not notify")

	// RFC 7009 §2.2: the revocation still answers 200 OK...
	rec = httptest.NewRecorder()
	srv.RevokeHandler().ServeHTTP(rec, formRequest("/revoke",
		url.Values{"token": {issued.AccessToken}}, true))
	assert.Equal(t, http.StatusOK, rec.Code)

	// ...and the failure surfaces through the hook only.
	got := sink.collected()
	require.NotEmpty(t, got)

	for _, e := range got {
		assert.Equal(t, oauth2.CodeServerError, oauth2.IsCode(e))
		assert.ErrorContains(t, e, "revoke")
	}

	assert.ErrorContains(t, got[0], "revoke access token failed")
}

func TestOnErrorSkipsUnknownRevocationTarget(t *testing.T) {
	t.Parallel()

	sink := &errorSink{}
	cfg := hookServerConfig(memory.New())
	cfg.OnError = sink.hook

	srv, err := oauth2.NewServer(cfg)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	srv.RevokeHandler().ServeHTTP(rec, formRequest("/revoke",
		url.Values{"token": {"never-issued"}}, true))

	// An unknown token is not an incident: 200 OK and no notification.
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, sink.codes())
}

func TestOnErrorReportsFailedFamilyRevocation(t *testing.T) {
	t.Parallel()

	sink := &errorSink{}
	store := &revokeFailingStore{Store: memory.New(), err: errors.New("revocation backend down")}
	cfg := hookServerConfig(store)
	cfg.OnError = sink.hook

	srv, err := oauth2.NewServer(cfg)
	require.NoError(t, err)

	raw := "refresh-to-revoke"
	require.NoError(t, store.SaveRefreshToken(t.Context(), &oauth2.RefreshToken{
		Token:     raw,
		TokenHash: oauth2.HashToken(nil, raw),
		ClientID:  testClientID,
		Subject:   "alice",
		Scope:     "api:read",
		FamilyID:  "family-1",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}))

	rec := httptest.NewRecorder()
	srv.RevokeHandler().ServeHTTP(rec, formRequest("/revoke", url.Values{"token": {raw}}, true))

	// RFC 7009 §2.2 still mandates 200 OK; the hook carries the failure.
	assert.Equal(t, http.StatusOK, rec.Code)

	got := sink.collected()
	require.Len(t, got, 1)
	assert.Equal(t, oauth2.CodeServerError, oauth2.IsCode(got[0]))
	assert.ErrorContains(t, got[0], "revoke refresh family failed")
	assert.ErrorContains(t, errors.Unwrap(got[0]), "revocation backend down")
}
