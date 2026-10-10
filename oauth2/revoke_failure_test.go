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
	"testing"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// unavailableBody is the /revoke answer when the revocation may not have
// taken effect (RFC 7009 §2.2.1).
const unavailableBody = `{"error":"temporarily_unavailable","error_description":"revocation temporarily unavailable"}`

// revokeStore fails, one switch each, the storage calls /revoke makes.
type revokeStore struct {
	*memory.Store

	accessLookupErr  error
	refreshLookupErr error
	revokeAccessErr  error
	revokeFamilyErr  error
}

func (s *revokeStore) LookupAccessToken(ctx context.Context, hash string) (*oauth2.AccessToken, error) {
	if s.accessLookupErr != nil {
		return nil, s.accessLookupErr
	}

	return s.Store.LookupAccessToken(ctx, hash)
}

func (s *revokeStore) LookupRefreshToken(ctx context.Context, hash string) (*oauth2.RefreshToken, error) {
	if s.refreshLookupErr != nil {
		return nil, s.refreshLookupErr
	}

	return s.Store.LookupRefreshToken(ctx, hash)
}

func (s *revokeStore) RevokeAccessToken(ctx context.Context, hash string) error {
	if s.revokeAccessErr != nil {
		return s.revokeAccessErr
	}

	return s.Store.RevokeAccessToken(ctx, hash)
}

func (s *revokeStore) RevokeRefreshFamily(ctx context.Context, familyID string) error {
	if s.revokeFamilyErr != nil {
		return s.revokeFamilyErr
	}

	return s.Store.RevokeRefreshFamily(ctx, familyID)
}

// revokeServer serves /revoke over store, reporting to sink.
func revokeServer(t *testing.T, store oauth2.Storage, sink *errorSink) *oauth2.Server {
	t.Helper()

	cfg := hookServerConfig(store)
	cfg.OnError = sink.hook

	srv, err := oauth2.NewServer(cfg)
	require.NoError(t, err)

	return srv
}

// revoke POSTs raw to /revoke as the test client.
func revoke(srv *oauth2.Server, raw string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	srv.RevokeHandler().ServeHTTP(rec, formRequest("/oauth2/revoke", url.Values{"token": {raw}}, true))

	return rec
}

// requireUnavailable asserts the 503 answer of a revocation that may not
// have taken effect, and that the hook received exactly the server_errors
// described by want — the 503 itself is not reported again.
func requireUnavailable(t *testing.T, rec *httptest.ResponseRecorder, sink *errorSink, want ...string) {
	t.Helper()

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.JSONEq(t, unavailableBody, rec.Body.String())
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.NotContains(t, rec.Body.String(), "backend down")

	requireReported(t, sink, want...)
}

// requireReported asserts the hook received one server_error per
// description in want, in order, each carrying the backend cause.
func requireReported(t *testing.T, sink *errorSink, want ...string) {
	t.Helper()

	got := sink.collected()
	require.Len(t, got, len(want))

	for i, desc := range want {
		assert.Equal(t, oauth2.CodeServerError, oauth2.IsCode(got[i]))
		assert.ErrorContains(t, got[i], desc)
		assert.ErrorContains(t, errors.Unwrap(got[i]), "backend down")
	}
}

func TestRevokeAnswersUnavailableWhenTheTokenMayStillBeUsable(t *testing.T) {
	t.Parallel()

	backendDown := errors.New("backend down")

	cases := []struct {
		name  string
		store func(*memory.Store) *revokeStore
		want  []string
	}{
		{
			"access token lookup failed",
			func(m *memory.Store) *revokeStore { return &revokeStore{Store: m, accessLookupErr: backendDown} },
			[]string{"revoke: token lookup failed"},
		},
		{
			"refresh token lookup failed",
			func(m *memory.Store) *revokeStore { return &revokeStore{Store: m, refreshLookupErr: backendDown} },
			[]string{"revoke: token lookup failed"},
		},
		{
			"refresh family revocation failed",
			func(m *memory.Store) *revokeStore { return &revokeStore{Store: m, revokeFamilyErr: backendDown} },
			[]string{"revoke refresh family failed"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sink := &errorSink{}
			store := tc.store(memory.New())
			srv := revokeServer(t, store, sink)

			// A refresh token: the access-token lookup misses it first.
			seedPair(t, store.Store, newClientPair("unavailable-rt", "fam-unavailable"))

			requireUnavailable(t, revoke(srv, "unavailable-rt"), sink, tc.want...)

			// Nothing was revoked, and a retry once the backend is back
			// revokes the token: the revocation is idempotent.
			rt, err := store.Store.LookupRefreshToken(t.Context(), oauth2.HashToken(nil, "unavailable-rt"))
			require.NoError(t, err)
			assert.False(t, rt.Consumed)

			retry := revokeServer(t, store.Store, &errorSink{})
			assert.Equal(t, http.StatusOK, revoke(retry, "unavailable-rt").Code)

			rt, err = store.Store.LookupRefreshToken(t.Context(), oauth2.HashToken(nil, "unavailable-rt"))
			require.NoError(t, err)
			assert.True(t, rt.Consumed)
		})
	}
}

func TestRevokeAccessTokenAnswersByTheTokenOutcome(t *testing.T) {
	t.Parallel()

	backendDown := errors.New("backend down")

	t.Run("the family revocation failed", func(t *testing.T) {
		t.Parallel()

		sink := &errorSink{}
		store := &revokeStore{Store: memory.New(), revokeFamilyErr: familyRevocationFailure("fam-failed")}
		pair := seedPair(t, store.Store, newClientPair("failed-rt", "fam-failed"))

		requireUnavailable(t, revoke(revokeServer(t, store, sink), pair.Access.Token), sink,
			"revoke refresh family failed")
		assert.ErrorContains(t, errors.Unwrap(sink.collected()[0]), `"fam-failed"`)

		// The access token was left in place, so the retry the 503 calls for
		// redoes both revocations once the backend is back.
		_, err := store.Store.LookupAccessToken(t.Context(), pair.Access.TokenHash)
		require.NoError(t, err, "the access token was not deleted")

		rec := revoke(revokeServer(t, store.Store, &errorSink{}), pair.Access.Token)
		assert.Equal(t, http.StatusOK, rec.Code)

		_, err = store.Store.LookupAccessToken(t.Context(), pair.Access.TokenHash)
		assert.Error(t, err, "the access token is revoked")

		rt, err := store.Store.LookupRefreshToken(t.Context(), pair.Refresh.TokenHash)
		require.NoError(t, err)
		assert.True(t, rt.Consumed, "the family's refresh token is revoked")
	})

	t.Run("the family revocation covers a failed delete", func(t *testing.T) {
		t.Parallel()

		sink := &errorSink{}
		store := &revokeStore{Store: memory.New(), revokeAccessErr: backendDown}
		pair := seedPair(t, store.Store, newClientPair("covered-rt", "fam-covered"))

		rec := revoke(revokeServer(t, store, sink), pair.Access.Token)
		assert.Equal(t, http.StatusOK, rec.Code, "the token is unusable through its revoked family")
		requireReported(t, sink, "revoke access token failed")

		_, err := store.LookupAccessToken(t.Context(), pair.Access.TokenHash)
		assert.ErrorIs(t, err, oauth2.ErrTokenFamilyRevoked)
	})

	t.Run("a token outside any family", func(t *testing.T) {
		t.Parallel()

		sink := &errorSink{}
		store := &revokeStore{Store: memory.New(), revokeAccessErr: backendDown}
		cc := newClientPair("cc-rt", "")
		cc.Access.FamilyID, cc.Refresh = "", nil
		seedPair(t, store.Store, cc)

		requireUnavailable(t, revoke(revokeServer(t, store, sink), cc.Access.Token), sink,
			"revoke access token failed")
	})
}

func TestRevokeLeavesOtherClientsTokensAlone(t *testing.T) {
	t.Parallel()

	sink := &errorSink{}
	store := memory.New()
	srv := revokeServer(t, store, sink)

	other := newClientPair("other-rt", "fam-other")
	other.Access.ClientID, other.Refresh.ClientID = "someone-else", "someone-else"
	seedPair(t, store, other)

	for _, raw := range []string{other.Access.Token, other.Refresh.Token} {
		rec := revoke(srv, raw)
		assert.Equal(t, http.StatusOK, rec.Code, "RFC 7009 §2.2: no hint the token exists")
	}

	assert.Empty(t, sink.collected())

	_, err := store.LookupAccessToken(t.Context(), other.Access.TokenHash)
	require.NoError(t, err, "a client cannot revoke another client's token")
}

func TestRevokeIsQuietForAlreadyRevokedFamilies(t *testing.T) {
	t.Parallel()

	sink := &errorSink{}
	store := memory.New()
	srv := revokeServer(t, store, sink)

	pair := seedPair(t, store, newClientPair("done-rt", "fam-done"))
	require.NoError(t, store.RevokeRefreshFamily(t.Context(), "fam-done"))

	for _, raw := range []string{pair.Access.Token, pair.Refresh.Token} {
		assert.Equal(t, http.StatusOK, revoke(srv, raw).Code)
	}

	assert.Empty(t, sink.collected(), "a revoked family's token reads like an unknown one")
}
