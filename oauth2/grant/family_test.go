// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grant_test

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/hyperscale-stack/security/oauth2/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errBackendDown is the backend failure the token-family tests inject.
var errBackendDown = errors.New("backend down")

// clientPair returns a pair issued to the test client in family: refresh
// token raw and access token raw+"-access", both valid until expiresAt.
func clientPair(raw, family, scope string, expiresAt time.Time) *oauth2.TokenPair {
	issuedAt := time.Now().Add(-time.Hour)

	return &oauth2.TokenPair{
		Access: oauth2.AccessToken{
			Token: raw + "-access", TokenHash: oauth2.HashToken(nil, raw+"-access"),
			ClientID: clientID, Subject: subject, Scope: scope, Audience: "api",
			FamilyID: family, IssuedAt: issuedAt, ExpiresAt: expiresAt,
		},
		Refresh: &oauth2.RefreshToken{
			Token: raw, TokenHash: oauth2.HashToken(nil, raw),
			ClientID: clientID, Subject: subject, Scope: scope,
			FamilyID: family, IssuedAt: issuedAt, ExpiresAt: expiresAt,
		},
	}
}

// seedPair persists clientPair(raw, family, scope, expiresAt) straight into
// store, the way a grant issues it, and returns it.
func seedPair(t *testing.T, store oauth2.Storage, raw, family, scope string, expiresAt time.Time) *oauth2.TokenPair {
	t.Helper()

	pair := clientPair(raw, family, scope, expiresAt)
	require.NoError(t, store.SaveTokenPair(t.Context(), pair))

	return pair
}

// seedRotated seeds a pair in family and rotates its refresh token raw, so
// that raw is consumed the only way a refresh token can be: by a real
// rotation. It returns the pair the rotation issued, still active.
func seedRotated(t *testing.T, store oauth2.Storage, raw, family string) *oauth2.TokenPair {
	t.Helper()

	expiresAt := time.Now().Add(time.Hour)
	seedPair(t, store, raw, family, "read:mail", expiresAt)

	next := clientPair(raw+"-next", family, "read:mail", expiresAt)
	require.NoError(t, store.RotateRefreshToken(t.Context(), oauth2.HashToken(nil, raw), next))

	return next
}

// persistCall is one persistence call a grant made on a familyStore.
type persistCall struct {
	kind    string // "save" or "rotate"
	oldHash string // the rotated refresh token, for "rotate"
	pair    oauth2.TokenPair
}

// familyStore decorates the memory store for the token-family grant tests:
// it records the grant's persistence calls, runs afterLookup once right
// after the grant's refresh-token lookup — a competing request landing at
// that exact point — and can force the result of a rotation or a family
// revocation. Seed through the embedded Store, so seeding is not recorded.
type familyStore struct {
	*memory.Store

	afterLookup func(*memory.Store)
	lookup      *oauth2.RefreshToken // served instead of the stored token
	saveErr     error
	rotateErr   error
	revokeErr   error

	calls   []persistCall
	revokes []revokeCall
}

// revokeCall records the context a family revocation ran on, as it was
// when the store received the call.
type revokeCall struct {
	ctxErr      error
	hasDeadline bool
}

func (s *familyStore) LookupRefreshToken(ctx context.Context, hash string) (*oauth2.RefreshToken, error) {
	if s.lookup != nil {
		rt := *s.lookup

		return &rt, nil
	}

	rt, err := s.Store.LookupRefreshToken(ctx, hash)

	if fn := s.afterLookup; fn != nil {
		s.afterLookup = nil
		fn(s.Store)
	}

	return rt, err
}

func (s *familyStore) SaveTokenPair(ctx context.Context, pair *oauth2.TokenPair) error {
	s.calls = append(s.calls, persistCall{kind: "save", pair: *pair})

	if s.saveErr != nil {
		return s.saveErr
	}

	return s.Store.SaveTokenPair(ctx, pair)
}

func (s *familyStore) RotateRefreshToken(ctx context.Context, oldHash string, next *oauth2.TokenPair) error {
	s.calls = append(s.calls, persistCall{kind: "rotate", oldHash: oldHash, pair: *next})

	if s.rotateErr != nil {
		return s.rotateErr
	}

	return s.Store.RotateRefreshToken(ctx, oldHash, next)
}

func (s *familyStore) RevokeRefreshFamily(ctx context.Context, familyID string) error {
	_, hasDeadline := ctx.Deadline()
	s.revokes = append(s.revokes, revokeCall{ctxErr: ctx.Err(), hasDeadline: hasDeadline})

	if s.revokeErr != nil {
		return s.revokeErr
	}

	return s.Store.RevokeRefreshFamily(ctx, familyID)
}

// revocationFailure is the error a conforming store returns when it cannot
// record family as revoked.
func revocationFailure(family string) error {
	return fmt.Errorf("store: revoke family %q: %w: %w", family, oauth2.ErrTokenFamilyRevocationFailed, errBackendDown)
}

// recordingAccessGen mints opaque access tokens and records their hashes,
// so a test can look a token up even when the grant never returned it.
type recordingAccessGen struct{ hashes []string }

func (g *recordingAccessGen) Generate(ctx context.Context, c token.AccessTokenClaims) (string, string, error) {
	raw, hash, err := newAccessGen().Generate(ctx, c)
	g.hashes = append(g.hashes, hash)

	return raw, hash, err
}

// failingAccessGen is an access-token generator that always fails.
type failingAccessGen struct{}

func (failingAccessGen) Generate(context.Context, token.AccessTokenClaims) (string, string, error) {
	return "", "", errBackendDown
}

// failingRefreshGen is a refresh-token generator that always fails.
type failingRefreshGen struct{}

func (failingRefreshGen) Generate(context.Context) (string, string, error) {
	return "", "", errBackendDown
}

// hookRecorder collects what a grant reports to its error hook.
type hookRecorder struct{ errs []error }

func (h *hookRecorder) hook(_ context.Context, err error) { h.errs = append(h.errs, err) }

// rotatingConfig is a rotating refresh_token grant configuration over store.
func rotatingConfig(store oauth2.Storage, hooks *hookRecorder) grant.Config {
	return grant.Config{
		Storage: store, AccessTokens: newAccessGen(), RefreshTokens: newRefreshGen(),
		AccessTTL: time.Hour, RefreshTTL: 24 * time.Hour, OnError: hooks.hook,
	}
}

// requireNoAccessToken asserts that no access token hash is usable.
func requireNoAccessToken(t *testing.T, store oauth2.Storage, hashes ...string) {
	t.Helper()

	for _, hash := range hashes {
		_, err := store.LookupAccessToken(t.Context(), hash)
		require.Error(t, err, "access token %s must not be usable", hash)
	}
}

func TestRefreshRotationFailureLeavesNoAccessToken(t *testing.T) {
	t.Parallel()

	store := &familyStore{Store: memory.New(), rotateErr: errBackendDown}
	seedPair(t, store.Store, "fail-rotate", "fam-fail", "read:mail", time.Now().Add(time.Hour))

	resp, err := grant.NewRefreshToken(rotatingConfig(store, &hookRecorder{})).
		Handle(t.Context(), refreshReq("fail-rotate", oauth2.Profile20BCP))
	assert.Nil(t, resp)
	assert.Equal(t, oauth2.CodeServerError, oauth2.IsCode(err))
	assert.NotContains(t, err.Error(), "backend down", "the cause stays off the wire")

	// One persistence call — the atomic rotation — so its failure leaves
	// nothing behind: no access token is persisted before it any more.
	require.Len(t, store.calls, 1)
	call := store.calls[0]
	assert.Equal(t, "rotate", call.kind)
	assert.Equal(t, oauth2.HashToken(nil, "fail-rotate"), call.oldHash)
	require.NotNil(t, call.pair.Refresh)
	assert.Equal(t, "fam-fail", call.pair.Access.FamilyID)
	assert.Equal(t, "fam-fail", call.pair.Refresh.FamilyID)

	requireNoAccessToken(t, store, call.pair.Access.TokenHash)

	presented, err := store.LookupRefreshToken(t.Context(), oauth2.HashToken(nil, "fail-rotate"))
	require.NoError(t, err)
	assert.False(t, presented.Consumed, "the failed rotation consumed nothing")
}

func TestRefreshGeneratorFailureLeavesNoAccessToken(t *testing.T) {
	t.Parallel()

	store := &familyStore{Store: memory.New()}
	seedPair(t, store.Store, "fail-gen", "fam-gen", "read:mail", time.Now().Add(time.Hour))

	access := &recordingAccessGen{}
	cfg := rotatingConfig(store, &hookRecorder{})
	cfg.AccessTokens = access
	cfg.RefreshTokens = failingRefreshGen{}

	resp, err := grant.NewRefreshToken(cfg).Handle(t.Context(), refreshReq("fail-gen", oauth2.Profile20BCP))
	assert.Nil(t, resp)
	assert.Equal(t, oauth2.CodeServerError, oauth2.IsCode(err))

	require.Len(t, access.hashes, 1, "the access token was minted")
	assert.Empty(t, store.calls, "nothing is persisted before the pair is complete")
	requireNoAccessToken(t, store, access.hashes...)
}

func TestAuthorizationCodeGeneratorFailureLeavesNoAccessToken(t *testing.T) {
	t.Parallel()

	store := &familyStore{Store: memory.New()}
	_, req := newAuthCodeReq(t.Context(), store.Store, true)

	access := &recordingAccessGen{}
	g := grant.NewAuthorizationCode(grant.Config{
		Storage: store, AccessTokens: access, RefreshTokens: failingRefreshGen{},
		AccessTTL: time.Hour, RefreshTTL: time.Hour,
	})

	resp, err := g.Handle(t.Context(), req)
	assert.Nil(t, resp)
	assert.Equal(t, oauth2.CodeServerError, oauth2.IsCode(err))

	require.Len(t, access.hashes, 1, "the access token was minted")
	assert.Empty(t, store.calls, "nothing is persisted before the pair is complete")
	requireNoAccessToken(t, store, access.hashes...)
}

func TestAuthorizationCodeIssuesOnePairAtomically(t *testing.T) {
	t.Parallel()

	store := &familyStore{Store: memory.New()}
	_, req := newAuthCodeReq(t.Context(), store.Store, true)
	g := grant.NewAuthorizationCode(grant.Config{
		Storage: store, AccessTokens: newAccessGen(), RefreshTokens: newRefreshGen(),
		AccessTTL: time.Hour, RefreshTTL: time.Hour,
	})

	resp, err := g.Handle(t.Context(), req)
	require.NoError(t, err)
	require.NotNil(t, resp.Pair.Refresh)

	require.Len(t, store.calls, 1)
	assert.Equal(t, "save", store.calls[0].kind)
	assert.Equal(t, resp.Pair, store.calls[0].pair)
	assert.NotEmpty(t, resp.Pair.Access.FamilyID)
	assert.Equal(t, resp.Pair.Access.FamilyID, resp.Pair.Refresh.FamilyID, "both tokens open one family")
}

// TestRefreshStoreReuseRevocationFailureIsReported covers the reuse the
// store detects while rotating — the token was consumed between the
// grant's lookup and its rotation — when the store could not revoke the
// family: the grant retries the revocation, and its failure is reported
// exactly once.
func TestRefreshStoreReuseRevocationFailureIsReported(t *testing.T) {
	t.Parallel()

	store := &familyStore{
		Store:     memory.New(),
		rotateErr: fmt.Errorf("%w: %w", oauth2.ErrRefreshTokenReused, revocationFailure("fam-reuse")),
		revokeErr: revocationFailure("fam-reuse"),
	}
	seedPair(t, store.Store, "store-reuse", "fam-reuse", "read:mail", time.Now().Add(time.Hour))

	hooks := &hookRecorder{}

	resp, err := grant.NewRefreshToken(rotatingConfig(store, hooks)).
		Handle(t.Context(), refreshReq("store-reuse", oauth2.Profile20BCP))
	assert.Nil(t, resp)
	assert.Same(t, oauth2.ErrRefreshTokenReused, err, "the client gets the bare reuse refusal")

	require.Len(t, store.revokes, 1, "the grant retried the revocation")
	require.Len(t, hooks.errs, 1, "one report per failed revocation")

	got := hooks.errs[0]
	assert.Equal(t, oauth2.CodeServerError, oauth2.IsCode(got))
	assert.ErrorContains(t, got, "revoke refresh family failed after reuse detection")
	assert.ErrorIs(t, got, oauth2.ErrTokenFamilyRevocationFailed)
	assert.ErrorContains(t, errors.Unwrap(got), `revoke family "fam-reuse"`)
	assert.ErrorContains(t, errors.Unwrap(got), "backend down")
	assert.NotErrorIs(t, got, oauth2.ErrRefreshTokenReused, "the report counts the revocation, not the reuse")
}

func TestRefreshStoreReuseRevocationRetried(t *testing.T) {
	t.Parallel()

	store := &familyStore{
		Store:     memory.New(),
		rotateErr: fmt.Errorf("%w: %w", oauth2.ErrRefreshTokenReused, revocationFailure("fam-retry")),
	}
	seed := seedPair(t, store.Store, "store-retry", "fam-retry", "read:mail", time.Now().Add(time.Hour))

	hooks := &hookRecorder{}

	_, err := grant.NewRefreshToken(rotatingConfig(store, hooks)).
		Handle(t.Context(), refreshReq("store-retry", oauth2.Profile20BCP))
	assert.Same(t, oauth2.ErrRefreshTokenReused, err)

	// The store's revocation failed, the grant's retry succeeded: the
	// family is revoked and there is nothing to report.
	assert.Len(t, store.revokes, 1)
	assert.Empty(t, hooks.errs)
	requireNoAccessToken(t, store, seed.Access.TokenHash)
}

// TestReuseRevocationDetachedFromRequest replays a consumed token on a
// request whose context is already canceled — a client that hung up: the
// revocation its replay triggers still runs, on a live context with a
// deadline.
func TestReuseRevocationDetachedFromRequest(t *testing.T) {
	t.Parallel()

	store := &familyStore{Store: memory.New()}
	next := seedRotated(t, store.Store, "detached", "fam-detached")
	hooks := &hookRecorder{}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := grant.NewRefreshToken(rotatingConfig(store, hooks)).Handle(ctx, refreshReq("detached", oauth2.Profile20BCP))
	assert.Same(t, oauth2.ErrRefreshTokenReused, err)

	require.Len(t, store.revokes, 1)
	assert.NoError(t, store.revokes[0].ctxErr, "the revocation is detached from the request's cancellation")
	assert.True(t, store.revokes[0].hasDeadline, "the detached revocation is bounded")
	assert.Empty(t, hooks.errs)

	requireNoAccessToken(t, store, next.Access.TokenHash)
}

// TestRefreshReusedBetweenLookupAndRotation lets a competing exchange of the
// same token land between the grant's lookup and its rotation: the store
// detects the reuse and revokes the family, the grant refuses quietly.
func TestRefreshReusedBetweenLookupAndRotation(t *testing.T) {
	t.Parallel()

	var attacker *oauth2.TokenPair

	store := &familyStore{Store: memory.New()}
	seedPair(t, store.Store, "raced", "fam-raced", "read:mail", time.Now().Add(time.Hour))

	store.afterLookup = func(inner *memory.Store) {
		attacker = clientPair("attacker", "fam-raced", "read:mail", time.Now().Add(time.Hour))
		require.NoError(t, inner.RotateRefreshToken(t.Context(), oauth2.HashToken(nil, "raced"), attacker))
	}

	hooks := &hookRecorder{}

	_, err := grant.NewRefreshToken(rotatingConfig(store, hooks)).Handle(t.Context(), refreshReq("raced", oauth2.Profile20BCP))
	assert.Same(t, oauth2.ErrRefreshTokenReused, err)
	assert.Empty(t, hooks.errs, "the store revoked the family: nothing to report")
	assert.Empty(t, store.revokes, "the grant does not revoke again")

	require.Len(t, store.calls, 1)
	requireNoAccessToken(t, store, attacker.Access.TokenHash, store.calls[0].pair.Access.TokenHash)

	rt, err := store.LookupRefreshToken(t.Context(), attacker.Refresh.TokenHash)
	require.NoError(t, err)
	assert.True(t, rt.Consumed, "the competing exchange's refresh token is revoked too")
}

// TestRefreshRevokedBetweenLookupAndRotation revokes the family between the
// grant's lookup and its rotation: the rotation is refused with
// ErrTokenFamilyRevoked and persists nothing.
func TestRefreshRevokedBetweenLookupAndRotation(t *testing.T) {
	t.Parallel()

	store := &familyStore{Store: memory.New()}
	seedPair(t, store.Store, "revoked-mid", "fam-mid", "read:mail", time.Now().Add(time.Hour))

	store.afterLookup = func(inner *memory.Store) {
		require.NoError(t, inner.RevokeRefreshFamily(t.Context(), "fam-mid"))
	}

	resp, err := grant.NewRefreshToken(rotatingConfig(store, &hookRecorder{})).
		Handle(t.Context(), refreshReq("revoked-mid", oauth2.Profile20BCP))
	assert.Nil(t, resp)
	require.ErrorIs(t, err, oauth2.ErrTokenFamilyRevoked)
	assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))

	require.Len(t, store.calls, 1)
	requireNoAccessToken(t, store, store.calls[0].pair.Access.TokenHash)

	_, err = store.LookupRefreshToken(t.Context(), store.calls[0].pair.Refresh.TokenHash)
	assert.Error(t, err, "the refused rotation persisted no refresh token")
}

// TestRefreshNonRotatingRefusedInRevokedFamily covers the legacy Profile20
// refresh: the family revoked between the lookup and the issuance refuses
// the new access token instead of letting it outlive the revocation.
func TestRefreshNonRotatingRefusedInRevokedFamily(t *testing.T) {
	t.Parallel()

	store := &familyStore{Store: memory.New()}
	seedPair(t, store.Store, "static-mid", "fam-static", "read:mail", time.Now().Add(time.Hour))

	store.afterLookup = func(inner *memory.Store) {
		require.NoError(t, inner.RevokeRefreshFamily(t.Context(), "fam-static"))
	}

	resp, err := grant.NewRefreshToken(grant.Config{Storage: store, AccessTokens: newAccessGen(), AccessTTL: time.Hour}).
		Handle(t.Context(), refreshReq("static-mid", oauth2.Profile20))
	assert.Nil(t, resp)
	require.ErrorIs(t, err, oauth2.ErrTokenFamilyRevoked)
	assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))

	require.Len(t, store.calls, 1)
	assert.Equal(t, "save", store.calls[0].kind)
	assert.Nil(t, store.calls[0].pair.Refresh)
	requireNoAccessToken(t, store, store.calls[0].pair.Access.TokenHash)
}

// TestRefreshRotationVanishedTokenIsInvalidGrant lets the store report the
// presented token unknown at rotation time — e.g. it expired from Redis
// since the lookup: that is an invalid grant (RFC 6749 §5.2), not a
// server error.
func TestRefreshRotationVanishedTokenIsInvalidGrant(t *testing.T) {
	t.Parallel()

	store := &familyStore{
		Store:     memory.New(),
		rotateErr: oauth2.ErrInvalidGrant.WithDescription("refresh token not found"),
	}
	seedPair(t, store.Store, "vanished", "fam-vanished", "read:mail", time.Now().Add(time.Hour))

	resp, err := grant.NewRefreshToken(rotatingConfig(store, &hookRecorder{})).
		Handle(t.Context(), refreshReq("vanished", oauth2.Profile20BCP))
	assert.Nil(t, resp)
	assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))
}

// TestIssuanceMapsStorageFailures covers the answer of a failed SaveTokenPair:
// a family refused as revoked keeps its invalid_grant — a replayed
// authorization code revokes the family of the exchange it races — while a
// backend failure is a server_error whose cause stays off the wire.
func TestIssuanceMapsStorageFailures(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		saveErr error
		code    string
	}{
		{"revoked family", oauth2.ErrTokenFamilyRevoked, oauth2.CodeInvalidGrant},
		{"backend failure", errBackendDown, oauth2.CodeServerError},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &familyStore{Store: memory.New(), saveErr: tc.saveErr}
			_, req := newAuthCodeReq(t.Context(), store.Store, true)
			g := grant.NewAuthorizationCode(grant.Config{
				Storage: store, AccessTokens: newAccessGen(), RefreshTokens: newRefreshGen(),
				AccessTTL: time.Hour, RefreshTTL: time.Hour,
			})

			resp, err := g.Handle(t.Context(), req)
			assert.Nil(t, resp)
			assert.Equal(t, tc.code, oauth2.IsCode(err))
			assert.ErrorIs(t, err, tc.saveErr, "the cause reaches the hook")
			require.Len(t, store.calls, 1)
		})
	}
}

func TestAccessGeneratorFailurePersistsNothing(t *testing.T) {
	t.Parallel()

	t.Run("authorization_code", func(t *testing.T) {
		t.Parallel()

		store := &familyStore{Store: memory.New()}
		_, req := newAuthCodeReq(t.Context(), store.Store, true)

		resp, err := grant.NewAuthorizationCode(grant.Config{
			Storage: store, AccessTokens: failingAccessGen{}, AccessTTL: time.Hour,
		}).Handle(t.Context(), req)
		assert.Nil(t, resp)
		assert.Equal(t, oauth2.CodeServerError, oauth2.IsCode(err))
		assert.Empty(t, store.calls)
	})

	t.Run("refresh_token", func(t *testing.T) {
		t.Parallel()

		store := &familyStore{Store: memory.New()}
		seedPair(t, store.Store, "no-access", "fam-no-access", "read:mail", time.Now().Add(time.Hour))

		cfg := rotatingConfig(store, &hookRecorder{})
		cfg.AccessTokens = failingAccessGen{}

		resp, err := grant.NewRefreshToken(cfg).Handle(t.Context(), refreshReq("no-access", oauth2.Profile20BCP))
		assert.Nil(t, resp)
		assert.Equal(t, oauth2.CodeServerError, oauth2.IsCode(err))
		assert.Empty(t, store.calls)
	})
}

func TestClientCredentialsStorageFailureIsServerError(t *testing.T) {
	t.Parallel()

	store := &familyStore{Store: memory.New(), saveErr: errBackendDown}

	resp, err := grant.NewClientCredentials(grant.Config{
		Storage: store, AccessTokens: newAccessGen(), AccessTTL: time.Hour,
	}).Handle(t.Context(), grant.Request{Client: newClient(), Form: url.Values{}, Now: time.Now()})
	assert.Nil(t, resp)
	assert.Equal(t, oauth2.CodeServerError, oauth2.IsCode(err))

	require.Len(t, store.calls, 1)
	assert.Empty(t, store.calls[0].pair.Access.FamilyID, "a client_credentials token belongs to no family")
	assert.Nil(t, store.calls[0].pair.Refresh)
}

// TestRefreshReuseWithoutFamilyRevokesNothing presents a consumed refresh
// token stored without a family — only a store predating token families
// holds one: it is refused as reuse, with no family to revoke.
func TestRefreshReuseWithoutFamilyRevokesNothing(t *testing.T) {
	t.Parallel()

	store := &familyStore{Store: memory.New(), lookup: &oauth2.RefreshToken{
		TokenHash: oauth2.HashToken(nil, "legacy"), ClientID: clientID, Subject: subject,
		Scope: "read:mail", ExpiresAt: time.Now().Add(time.Hour), Consumed: true,
	}}
	hooks := &hookRecorder{}

	_, err := grant.NewRefreshToken(rotatingConfig(store, hooks)).Handle(t.Context(), refreshReq("legacy", oauth2.Profile20BCP))
	assert.Same(t, oauth2.ErrRefreshTokenReused, err)
	assert.Empty(t, store.revokes, "RevokeRefreshFamily refuses the empty family id")
	assert.Empty(t, hooks.errs)
}
