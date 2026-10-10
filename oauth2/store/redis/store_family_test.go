// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package redisstore_test

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/hyperscale-stack/security/oauth2"
	redisstore "github.com/hyperscale-stack/security/oauth2/store/redis"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errInjected is the backend failure the script hooks inject.
var errInjected = errors.New("injected failure")

// Key layout of the default "oauth2:" prefix.
func famKey(id string) string  { return "oauth2:fam:" + id }
func rtKey(hash string) string { return "oauth2:rt:" + hash }
func atKey(hash string) string { return "oauth2:at:" + hash }

// testPair returns a pair in family whose tokens both expire after ttl.
func testPair(name, family string, ttl time.Duration) *oauth2.TokenPair {
	now := time.Now()

	return &oauth2.TokenPair{
		Access: oauth2.AccessToken{
			TokenHash: "at-" + name, ClientID: "c", Subject: "s", Scope: "r", Audience: "api",
			FamilyID: family, IssuedAt: now, ExpiresAt: now.Add(ttl),
		},
		Refresh: &oauth2.RefreshToken{
			TokenHash: "rt-" + name, ClientID: "c", Subject: "s", Scope: "r",
			FamilyID: family, IssuedAt: now, ExpiresAt: now.Add(ttl),
		},
	}
}

// scriptHook intercepts the store's Lua scripts, matched by their key
// count and first key. Scripts run through EVALSHA, then EVAL after a
// NOSCRIPT reply, so the hook acts BEFORE a matching command and never
// inspects its result. While armed it either runs before once — a
// competing operation landing right before the script — or fails the
// script without sending it.
type scriptHook struct {
	numKeys int
	key     string
	armed   atomic.Bool
	before  func()
	fail    error
}

func (h *scriptHook) DialHook(next redis.DialHook) redis.DialHook { return next }

func (h *scriptHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func (h *scriptHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if !h.matches(cmd) {
			return next(ctx, cmd)
		}

		if h.fail != nil && h.armed.Load() {
			return h.fail
		}

		if h.before != nil && h.armed.CompareAndSwap(true, false) {
			h.before()
		}

		return next(ctx, cmd)
	}
}

func (h *scriptHook) matches(cmd redis.Cmder) bool {
	args := cmd.Args()

	return (cmd.Name() == "evalsha" || cmd.Name() == "eval") &&
		len(args) > 3 && args[2] == h.numKeys && args[3] == h.key
}

// The scripts the hooks target, by key count and first key.
func revokeScript(family string) (int, string)  { return 1, famKey(family) }
func rotateScript(oldHash string) (int, string) { return 4, rtKey(oldHash) }
func issueScript(family string) (int, string)   { return 3, famKey(family) }

// hookedStores returns two stores over one miniredis: hooked, whose client
// carries hook, and plain, the one competing operations go through.
func hookedStores(t *testing.T, hook *scriptHook) (hooked, plain *redisstore.Store, mr *miniredis.Miniredis) {
	t.Helper()

	mr = miniredis.RunT(t)

	hookedClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	hookedClient.AddHook(hook)
	plainClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	t.Cleanup(func() {
		_ = hookedClient.Close()
		_ = plainClient.Close()
	})

	hooked, err := redisstore.New(hookedClient)
	require.NoError(t, err)

	plain, err = redisstore.New(plainClient)
	require.NoError(t, err)

	return hooked, plain, mr
}

func requireUsable(t *testing.T, s oauth2.Storage, pair *oauth2.TokenPair) {
	t.Helper()

	_, err := s.LookupAccessToken(t.Context(), pair.Access.TokenHash)
	require.NoError(t, err)

	rt, err := s.LookupRefreshToken(t.Context(), pair.Refresh.TokenHash)
	require.NoError(t, err)
	assert.False(t, rt.Consumed, "refresh token %s", pair.Refresh.TokenHash)
}

func requireUnusable(t *testing.T, s oauth2.Storage, pair *oauth2.TokenPair) {
	t.Helper()

	_, err := s.LookupAccessToken(t.Context(), pair.Access.TokenHash)
	assert.ErrorIs(t, err, oauth2.ErrTokenFamilyRevoked)

	rt, err := s.LookupRefreshToken(t.Context(), pair.Refresh.TokenHash)
	require.NoError(t, err)
	assert.True(t, rt.Consumed, "refresh token %s", pair.Refresh.TokenHash)
}

// requireNoKeys asserts that none of pair's tokens reached Redis.
func requireNoKeys(t *testing.T, mr *miniredis.Miniredis, pair *oauth2.TokenPair) {
	t.Helper()

	assert.False(t, mr.Exists(atKey(pair.Access.TokenHash)), "access token %s", pair.Access.TokenHash)
	assert.False(t, mr.Exists(rtKey(pair.Refresh.TokenHash)), "refresh token %s", pair.Refresh.TokenHash)
}

func requireFamily(t *testing.T, mr *miniredis.Miniredis, family, want string) {
	t.Helper()

	got, err := mr.Get(famKey(family))
	require.NoError(t, err)
	assert.Equal(t, want, got, "family %s", family)
}

func TestRedisRevokeFamilyFailureIsReported(t *testing.T) {
	t.Parallel()

	hook := &scriptHook{fail: errInjected}
	hook.numKeys, hook.key = revokeScript("fam-revoke")
	store, _, mr := hookedStores(t, hook)

	pair := testPair("revoke", "fam-revoke", time.Hour)
	require.NoError(t, store.SaveTokenPair(t.Context(), pair))

	hook.armed.Store(true)

	err := store.RevokeRefreshFamily(t.Context(), "fam-revoke")
	require.ErrorIs(t, err, oauth2.ErrTokenFamilyRevocationFailed)
	require.ErrorIs(t, err, errInjected)
	assert.Empty(t, oauth2.IsCode(err), "not an OAuth2 error: a caller answers server_error")
	assert.ErrorContains(t, err, `"fam-revoke"`)

	requireFamily(t, mr, "fam-revoke", "active")
	requireUsable(t, store, pair)

	hook.armed.Store(false)
	require.NoError(t, store.RevokeRefreshFamily(t.Context(), "fam-revoke"))
	requireFamily(t, mr, "fam-revoke", "revoked")
	requireUnusable(t, store, pair)
}

func TestRedisReuseRevocationFailureIsReported(t *testing.T) {
	t.Parallel()

	hook := &scriptHook{fail: errInjected}
	hook.numKeys, hook.key = revokeScript("fam-reuse")
	store, _, mr := hookedStores(t, hook)

	first := testPair("reuse-0", "fam-reuse", time.Hour)
	second := testPair("reuse-1", "fam-reuse", time.Hour)
	replay := testPair("reuse-2", "fam-reuse", time.Hour)

	require.NoError(t, store.SaveTokenPair(t.Context(), first))
	require.NoError(t, store.RotateRefreshToken(t.Context(), first.Refresh.TokenHash, second))

	hook.armed.Store(true)

	err := store.RotateRefreshToken(t.Context(), first.Refresh.TokenHash, replay)
	require.ErrorIs(t, err, oauth2.ErrRefreshTokenReused)
	require.ErrorIs(t, err, oauth2.ErrTokenFamilyRevocationFailed)
	require.ErrorIs(t, err, errInjected)
	assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))
	assert.ErrorContains(t, err, `"fam-reuse"`)

	// The store says the family is NOT revoked, and it is not.
	requireFamily(t, mr, "fam-reuse", "active")
	requireUsable(t, store, second)
	requireNoKeys(t, mr, replay)

	hook.armed.Store(false)
	require.NoError(t, store.RevokeRefreshFamily(t.Context(), "fam-reuse"))
	requireUnusable(t, store, second)
}

// TestRedisRotationJustBeforeRevocation lands a rotation right before the
// revocation script: the rotation is ordered before the revocation, which
// then covers its tokens.
func TestRedisRotationJustBeforeRevocation(t *testing.T) {
	t.Parallel()

	hook := &scriptHook{}
	hook.numKeys, hook.key = revokeScript("fam-race")
	store, plain, _ := hookedStores(t, hook)

	first := testPair("race-0", "fam-race", time.Hour)
	next := testPair("race-1", "fam-race", time.Hour)
	require.NoError(t, store.SaveTokenPair(t.Context(), first))

	hook.before = func() {
		require.NoError(t, plain.RotateRefreshToken(t.Context(), first.Refresh.TokenHash, next))
	}
	hook.armed.Store(true)

	require.NoError(t, store.RevokeRefreshFamily(t.Context(), "fam-race"))
	assert.False(t, hook.armed.Load(), "the rotation ran")

	requireUnusable(t, store, first)
	requireUnusable(t, store, next)
}

// TestRedisRevocationJustBeforeRotation lands a revocation right before the
// rotation script: the rotation is refused and writes nothing.
func TestRedisRevocationJustBeforeRotation(t *testing.T) {
	t.Parallel()

	first := testPair("late-0", "fam-late", time.Hour)
	next := testPair("late-1", "fam-late", time.Hour)

	hook := &scriptHook{}
	hook.numKeys, hook.key = rotateScript(first.Refresh.TokenHash)
	store, plain, mr := hookedStores(t, hook)

	require.NoError(t, store.SaveTokenPair(t.Context(), first))

	hook.before = func() {
		require.NoError(t, plain.RevokeRefreshFamily(t.Context(), "fam-late"))
	}
	hook.armed.Store(true)

	err := store.RotateRefreshToken(t.Context(), first.Refresh.TokenHash, next)
	require.ErrorIs(t, err, oauth2.ErrTokenFamilyRevoked)
	requireNoKeys(t, mr, next)

	raw, err := mr.Get(rtKey(first.Refresh.TokenHash))
	require.NoError(t, err)
	assert.Contains(t, raw, `"consumed":false`, "the refused rotation consumed nothing")
	requireUnusable(t, store, first)
}

// TestRedisRotationBetweenReuseAndRevocation lets an attacker rotate the
// family between the script that detects a reuse and the revocation the
// store then runs: the revocation covers the attacker's tokens too.
func TestRedisRotationBetweenReuseAndRevocation(t *testing.T) {
	t.Parallel()

	hook := &scriptHook{}
	hook.numKeys, hook.key = revokeScript("fam-gap")
	store, plain, _ := hookedStores(t, hook)

	first := testPair("gap-0", "fam-gap", time.Hour)
	second := testPair("gap-1", "fam-gap", time.Hour)
	attacker := testPair("gap-attacker", "fam-gap", time.Hour)

	require.NoError(t, store.SaveTokenPair(t.Context(), first))
	require.NoError(t, store.RotateRefreshToken(t.Context(), first.Refresh.TokenHash, second))

	hook.before = func() {
		require.NoError(t, plain.RotateRefreshToken(t.Context(), second.Refresh.TokenHash, attacker))
	}
	hook.armed.Store(true)

	err := store.RotateRefreshToken(t.Context(), first.Refresh.TokenHash, testPair("gap-2", "fam-gap", time.Hour))
	assert.Same(t, oauth2.ErrRefreshTokenReused, err)
	assert.False(t, hook.armed.Load(), "the attacker's rotation ran")

	requireUnusable(t, store, second)
	requireUnusable(t, store, attacker)
}

// TestRedisIssuanceAroundRevocation orders an issuance and a revocation
// both ways: an issuance landing right before the revocation script is
// covered by the revocation, one landing right after it is refused.
func TestRedisIssuanceAroundRevocation(t *testing.T) {
	t.Parallel()

	t.Run("issuance just before the revocation", func(t *testing.T) {
		t.Parallel()

		hook := &scriptHook{}
		hook.numKeys, hook.key = revokeScript("fam-issue")
		store, plain, _ := hookedStores(t, hook)

		pair := testPair("issue-before", "fam-issue", time.Hour)
		hook.before = func() { require.NoError(t, plain.SaveTokenPair(t.Context(), pair)) }
		hook.armed.Store(true)

		require.NoError(t, store.RevokeRefreshFamily(t.Context(), "fam-issue"))
		requireUnusable(t, store, pair)
	})

	t.Run("revocation just before the issuance", func(t *testing.T) {
		t.Parallel()

		hook := &scriptHook{}
		hook.numKeys, hook.key = issueScript("fam-issue")
		store, plain, mr := hookedStores(t, hook)

		hook.before = func() { require.NoError(t, plain.RevokeRefreshFamily(t.Context(), "fam-issue")) }
		hook.armed.Store(true)

		pair := testPair("issue-after", "fam-issue", time.Hour)
		require.ErrorIs(t, store.SaveTokenPair(t.Context(), pair), oauth2.ErrTokenFamilyRevoked)
		requireNoKeys(t, mr, pair)
	})
}

// resendHook runs the rotation script twice, the way go-redis resends a
// command whose reply was lost: the store must see the rotation succeed,
// not mistake its own first run for a reuse.
type resendHook struct{ scriptHook }

func (h *resendHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if h.matches(cmd) {
			if err := next(ctx, cmd); err != nil {
				return err // NOSCRIPT: go-redis falls back to EVAL
			}
		}

		return next(ctx, cmd)
	}
}

func TestRedisResentRotationIsNotReuse(t *testing.T) {
	t.Parallel()

	first := testPair("resend-0", "fam-resend", time.Hour)
	next := testPair("resend-1", "fam-resend", time.Hour)

	hook := &resendHook{}
	hook.numKeys, hook.key = rotateScript(first.Refresh.TokenHash)

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	client.AddHook(hook)
	t.Cleanup(func() { _ = client.Close() })

	store, err := redisstore.New(client)
	require.NoError(t, err)

	require.NoError(t, store.SaveTokenPair(t.Context(), first))
	require.NoError(t, store.RotateRefreshToken(t.Context(), first.Refresh.TokenHash, next))

	requireFamily(t, mr, "fam-resend", "active")
	requireUsable(t, store, next)
}

func TestRedisFamilyKeyTTL(t *testing.T) {
	t.Parallel()

	store, _, mr := hookedStores(t, &scriptHook{})
	ctx := t.Context()
	day := oauth2.FamilyRevocationRetention

	// The family lives as long as its longest token...
	first := testPair("ttl-0", "fam-ttl", time.Hour)
	require.NoError(t, store.SaveTokenPair(ctx, first))
	assert.InDelta(t, time.Hour, mr.TTL(famKey("fam-ttl")), float64(time.Second))

	long := testPair("ttl-1", "fam-ttl", 48*time.Hour)
	require.NoError(t, store.RotateRefreshToken(ctx, first.Refresh.TokenHash, long))
	assert.InDelta(t, 48*time.Hour, mr.TTL(famKey("fam-ttl")), float64(time.Second))

	// ...never shrinks with a shorter one...
	short := testPair("ttl-2", "fam-ttl", time.Minute)
	require.NoError(t, store.RotateRefreshToken(ctx, long.Refresh.TokenHash, short))
	assert.InDelta(t, 48*time.Hour, mr.TTL(famKey("fam-ttl")), float64(time.Second))

	// ...and rotating keeps the TTL of the consumed token.
	assert.InDelta(t, time.Hour, mr.TTL(rtKey(first.Refresh.TokenHash)), float64(time.Second))

	// A revocation keeps the longer of the family's TTL and the retention.
	require.NoError(t, store.RevokeRefreshFamily(ctx, "fam-ttl"))
	assert.InDelta(t, 48*time.Hour, mr.TTL(famKey("fam-ttl")), float64(time.Second))

	brief := testPair("ttl-brief", "fam-brief", time.Minute)
	require.NoError(t, store.SaveTokenPair(ctx, brief))
	require.NoError(t, store.RevokeRefreshFamily(ctx, "fam-brief"))
	assert.InDelta(t, day, mr.TTL(famKey("fam-brief")), float64(time.Second))

	// A revocation before issuance is retained for the retention too, and
	// outlives the tokens it refuses.
	require.NoError(t, store.RevokeRefreshFamily(ctx, "fam-unknown"))
	assert.InDelta(t, day, mr.TTL(famKey("fam-unknown")), float64(time.Second))

	mr.FastForward(2 * time.Minute)
	assert.False(t, mr.Exists(rtKey(brief.Refresh.TokenHash)), "the tokens expired")
	requireFamily(t, mr, "fam-brief", "revoked")
	require.ErrorIs(t, store.SaveTokenPair(ctx, testPair("ttl-late", "fam-brief", time.Hour)), oauth2.ErrTokenFamilyRevoked)
}

// TestRedisLookupFailsClosed covers family state that is missing or not
// what the store wrote: the family's tokens are never usable, and an
// unreadable state is an error, not an answer.
func TestRedisLookupFailsClosed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		state func(mr *miniredis.Miniredis, key string)
	}{
		{"missing", func(mr *miniredis.Miniredis, key string) { mr.Del(key) }},
		{"unexpected value", func(mr *miniredis.Miniredis, key string) { _ = mr.Set(key, "bogus") }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store, _, mr := hookedStores(t, &scriptHook{})
			pair := testPair("closed", "fam-closed", time.Hour)
			require.NoError(t, store.SaveTokenPair(t.Context(), pair))

			tc.state(mr, famKey("fam-closed"))

			requireUnusable(t, store, pair)

			next := testPair("closed-next", "fam-closed", time.Hour)
			err := store.RotateRefreshToken(t.Context(), pair.Refresh.TokenHash, next)
			require.ErrorIs(t, err, oauth2.ErrTokenFamilyRevoked)
			requireNoKeys(t, mr, next)

			// A rotation never creates the family.
			state, _ := mr.Get(famKey("fam-closed"))
			assert.NotEqual(t, "active", state)
		})
	}

	t.Run("unreadable", func(t *testing.T) {
		t.Parallel()

		store, _, mr := hookedStores(t, &scriptHook{})
		pair := testPair("wrongtype", "fam-wrongtype", time.Hour)
		require.NoError(t, store.SaveTokenPair(t.Context(), pair))

		mr.Del(famKey("fam-wrongtype"))
		_, err := mr.Lpush(famKey("fam-wrongtype"), "x")
		require.NoError(t, err)

		at, err := store.LookupAccessToken(t.Context(), pair.Access.TokenHash)
		assert.Nil(t, at)
		require.ErrorContains(t, err, "WRONGTYPE")

		rt, err := store.LookupRefreshToken(t.Context(), pair.Refresh.TokenHash)
		assert.Nil(t, rt)
		require.ErrorContains(t, err, "WRONGTYPE")

		require.Error(t, store.SaveTokenPair(t.Context(), testPair("wrongtype-2", "fam-wrongtype", time.Hour)))
	})
}

// TestRedisIssuanceRefusesUnexpectedFamilyState refuses to join a family
// whose state is neither unknown nor "active".
func TestRedisIssuanceRefusesUnexpectedFamilyState(t *testing.T) {
	t.Parallel()

	store, _, mr := hookedStores(t, &scriptHook{})
	require.NoError(t, mr.Set(famKey("fam-odd"), "bogus"))

	pair := testPair("odd", "fam-odd", time.Hour)
	require.ErrorIs(t, store.SaveTokenPair(t.Context(), pair), oauth2.ErrTokenFamilyRevoked)
	requireNoKeys(t, mr, pair)
}

// TestRedisRefreshTokenWithoutFamilyIsConsumed covers a refresh token
// stored without a family — only a build predating #82 could write one: it
// can no longer be exchanged.
func TestRedisRefreshTokenWithoutFamilyIsConsumed(t *testing.T) {
	t.Parallel()

	store, _, mr := hookedStores(t, &scriptHook{})
	require.NoError(t, mr.Set(rtKey("legacy"),
		`{"client_id":"c","subject":"s","scope":"r","family_id":"","consumed":false,"issued_at":0,"expires_at":0}`))

	rt, err := store.LookupRefreshToken(t.Context(), "legacy")
	require.NoError(t, err)
	assert.True(t, rt.Consumed)
}

// TestRedisNoFamilySets checks that the store no longer keeps the per-family
// member sets of earlier builds: nothing enumerates a family any more.
func TestRedisNoFamilySets(t *testing.T) {
	t.Parallel()

	store, _, mr := hookedStores(t, &scriptHook{})
	ctx := t.Context()

	first := testPair("sets-0", "fam-sets", time.Hour)
	require.NoError(t, store.SaveTokenPair(ctx, first))
	require.NoError(t, store.RotateRefreshToken(ctx, first.Refresh.TokenHash, testPair("sets-1", "fam-sets", time.Hour)))
	require.NoError(t, store.RevokeRefreshFamily(ctx, "fam-sets"))

	for _, key := range mr.Keys() {
		assert.False(t, strings.Contains(key, "famrt:") || strings.Contains(key, "famat:"), key)
	}
}
