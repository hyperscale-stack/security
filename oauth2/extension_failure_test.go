// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errSigningDown is the failure of the extension tests' id_token signer.
var errSigningDown = errors.New("signing key unavailable")

// failingExtension fails the token-response hook with err.
func failingExtension(err error) *fakeExtension {
	return &fakeExtension{
		extend: func(context.Context, oauth2.TokenIssuance) (oauth2.TokenResponseExtension, error) {
			return oauth2.TokenResponseExtension{}, err
		},
	}
}

// requireNoTokens asserts that rec carries no token at all.
func requireNoTokens(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()

	body := jsonBody(t, rec)
	assert.NotContains(t, body, "id_token")
	assert.NotContains(t, body, "access_token")
	assert.NotContains(t, body, "refresh_token")
}

// TestExtensionFailureAtTheCodeExchangePersistsNothing: when the hook
// fails, the exchange answers server_error — the cause reaching the hook —
// no token is persisted, and the code stays consumed: a retry is a replay.
func TestExtensionFailureAtTheCodeExchangePersistsNothing(t *testing.T) {
	t.Parallel()

	store := &writeCountingStore{Store: memory.New()}
	env := newExtensionEnv(t, failingExtension(errSigningDown), withStore(store))

	code := env.code(t, oidcQuery(), approve)
	writes := store.writes.Load()

	rec := env.exchange(code)
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, oauth2.CodeServerError, jsonBody(t, rec)["error"])
	requireNoTokens(t, rec)
	assert.Equal(t, writes, store.writes.Load(), "nothing persisted")

	hooked := env.sink.collected()
	require.Len(t, hooked, 1)
	assert.ErrorIs(t, hooked[0], errSigningDown)

	rec = env.exchange(code)
	require.Equal(t, http.StatusBadRequest, rec.Code, "the code was consumed")
	assert.Equal(t, oauth2.CodeInvalidGrant, jsonBody(t, rec)["error"])
}

// TestExtensionInvalidGrantPassesThrough: an extension refusing the grant
// with invalid_grant — e.g. a code not issued for an OpenID Connect request
// (OIDC Core §3.1.3.2) — answers it; any other *Error is a server_error.
func TestExtensionInvalidGrantPassesThrough(t *testing.T) {
	t.Parallel()

	refusal := oauth2.ErrInvalidGrant.WithDescription("code not issued for an OpenID Connect request")

	env := newExtensionEnv(t, failingExtension(refusal))

	rec := env.exchange(env.code(t, oidcQuery(), approve))
	require.Equal(t, http.StatusBadRequest, rec.Code)

	body := jsonBody(t, rec)
	assert.Equal(t, oauth2.CodeInvalidGrant, body["error"])
	assert.Equal(t, refusal.Description, body["error_description"])
	requireNoTokens(t, rec)

	env = newExtensionEnv(t, failingExtension(oauth2.ErrInvalidScope))

	rec = env.exchange(env.code(t, oidcQuery(), approve))
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, oauth2.CodeServerError, jsonBody(t, rec)["error"])
}

// failingWritesStore fails every token write.
type failingWritesStore struct {
	*memory.Store

	attempts atomic.Int32
}

var errStoreDown = errors.New("store down")

func (s *failingWritesStore) SaveTokenPair(context.Context, *oauth2.TokenPair) error {
	s.attempts.Add(1)

	return errStoreDown
}

func (s *failingWritesStore) RotateRefreshToken(context.Context, string, *oauth2.TokenPair) error {
	s.attempts.Add(1)

	return errStoreDown
}

// TestPersistenceFailureAfterTheExtensionReturnsNoIDToken: the hook ran and
// returned an id_token, the persistence then failed: the answer is a bare
// server_error — the id_token is dropped with the tokens.
func TestPersistenceFailureAfterTheExtensionReturnsNoIDToken(t *testing.T) {
	t.Parallel()

	ext := recordingExtension()
	store := &failingWritesStore{Store: memory.New()}
	env := newExtensionEnv(t, ext, withStore(store))

	rec := env.exchange(env.code(t, oidcQuery(), approve))
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	requireNoTokens(t, rec)
	assert.Len(t, ext.issuances, 1, "the hook ran before the write")
	assert.Equal(t, int32(1), store.attempts.Load())
}

// TestExtensionFailureAtRefreshLeavesTheTokenUsable: a refresh whose hook
// fails persists nothing and consumes nothing — the client retries with
// the same refresh token — and so does a rotation that fails after the
// hook, which answers no id_token.
func TestExtensionFailureAtRefreshLeavesTheTokenUsable(t *testing.T) {
	t.Parallel()

	var failing atomic.Bool
	ext := recordingExtension()
	inner := ext.extend
	ext.extend = func(ctx context.Context, ti oauth2.TokenIssuance) (oauth2.TokenResponseExtension, error) {
		if failing.Load() {
			return oauth2.TokenResponseExtension{}, errSigningDown
		}

		return inner(ctx, ti)
	}

	store := &writeCountingStore{Store: memory.New()}
	env := newExtensionEnv(t, ext, withStore(store))

	rec := env.exchange(env.code(t, oidcQuery(), approve))
	require.Equal(t, http.StatusOK, rec.Code)

	rt := jsonBody(t, rec)["refresh_token"].(string)
	writes := store.writes.Load()

	failing.Store(true)

	rec = env.refresh(rt)
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	requireNoTokens(t, rec)
	assert.Equal(t, writes, store.writes.Load(), "nothing persisted")

	stored, err := env.store.LookupRefreshToken(t.Context(), oauth2.HashToken(nil, rt))
	require.NoError(t, err)
	assert.False(t, stored.Consumed, "the presented token was not consumed")

	failing.Store(false)

	rec = env.refresh(rt)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "id-token-refresh_token", jsonBody(t, rec)["id_token"])
}

// TestRotationFailureAfterTheExtensionReturnsNoIDToken: the refresh hook
// ran, the rotation failed: a bare server_error.
func TestRotationFailureAfterTheExtensionReturnsNoIDToken(t *testing.T) {
	t.Parallel()

	ext := recordingExtension()
	store := &rotationFailingStore{Store: memory.New()}
	env := newExtensionEnv(t, ext, withStore(store))

	rec := env.exchange(env.code(t, oidcQuery(), approve))
	require.Equal(t, http.StatusOK, rec.Code)

	rec = env.refresh(jsonBody(t, rec)["refresh_token"].(string))
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	requireNoTokens(t, rec)
	assert.Len(t, ext.issuances, 2)
}

// rotationFailingStore fails every rotation.
type rotationFailingStore struct{ *memory.Store }

func (*rotationFailingStore) RotateRefreshToken(context.Context, string, *oauth2.TokenPair) error {
	return errStoreDown
}

// TestCodeReplayDuringTheExtensionWinsOverIt replays the code while the
// first exchange runs the hook: the proven replay revokes the code's
// family, so the exchange in flight cannot persist its pair and answers
// invalid_grant without its id_token (RFC 6749 §4.1.2, #80).
func TestCodeReplayDuringTheExtensionWinsOverIt(t *testing.T) {
	t.Parallel()

	var (
		env    *extensionEnv
		code   string
		replay *httptest.ResponseRecorder
	)

	ext := &fakeExtension{
		extend: func(context.Context, oauth2.TokenIssuance) (oauth2.TokenResponseExtension, error) {
			if replay == nil {
				replay = env.exchange(code)
			}

			return oauth2.TokenResponseExtension{IDToken: "minted"}, nil
		},
	}
	env = newExtensionEnv(t, ext)
	code = env.code(t, oidcQuery(), approve)

	rec := env.exchange(code)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, oauth2.CodeInvalidGrant, jsonBody(t, rec)["error"])
	requireNoTokens(t, rec)

	require.NotNil(t, replay)
	assert.Equal(t, http.StatusBadRequest, replay.Code)
	requireNoTokens(t, replay)
}

// TestConcurrentCodeExchangesReachTheExtensionOnce: 50 clients race to
// redeem one code. Only the consume winner reaches the hook; at most one
// exchange succeeds — a loser's proven replay may revoke the family first,
// then none does — and only a success carries an id_token.
func TestConcurrentCodeExchangesReachTheExtensionOnce(t *testing.T) {
	t.Parallel()

	ext := recordingExtension()
	env := newExtensionEnv(t, ext)
	code := env.code(t, oidcQuery(), approve)

	const n = 50

	recs := make([]*httptest.ResponseRecorder, n)
	start := make(chan struct{})

	var wg sync.WaitGroup

	for i := range n {
		wg.Go(func() {
			<-start

			recs[i] = env.exchange(code)
		})
	}

	close(start)
	wg.Wait()

	wins := 0

	for _, rec := range recs {
		body := jsonBody(t, rec)
		if rec.Code == http.StatusOK {
			wins++

			assert.Equal(t, "id-token-authorization_code", body["id_token"])

			continue
		}

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.NotContains(t, body, "id_token")
	}

	assert.LessOrEqual(t, wins, 1)

	_, _, extended := ext.calls()
	assert.Equal(t, 1, extended, "only the consume winner reaches the hook")
}

// TestConcurrentRefreshesWithTheExtension: 20 clients race to rotate one
// refresh token: exactly one succeeds, with its id_token; every loser gets
// invalid_grant without one (RFC 9700 §4.14.2).
func TestConcurrentRefreshesWithTheExtension(t *testing.T) {
	t.Parallel()

	env := newExtensionEnv(t, recordingExtension())

	rec := env.exchange(env.code(t, oidcQuery(), approve))
	require.Equal(t, http.StatusOK, rec.Code)

	rt := jsonBody(t, rec)["refresh_token"].(string)

	const n = 20

	recs := make([]*httptest.ResponseRecorder, n)
	start := make(chan struct{})

	var wg sync.WaitGroup

	for i := range n {
		wg.Go(func() {
			<-start

			recs[i] = env.refresh(rt)
		})
	}

	close(start)
	wg.Wait()

	wins := 0

	for _, rec := range recs {
		body := jsonBody(t, rec)
		if rec.Code == http.StatusOK {
			wins++

			assert.Equal(t, "id-token-refresh_token", body["id_token"])

			continue
		}

		assert.Equal(t, oauth2.CodeInvalidGrant, body["error"])
		assert.NotContains(t, body, "id_token")
	}

	assert.Equal(t, 1, wins)
}
