// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package redisstore_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	samlsp "github.com/hyperscale-stack/security/saml/sp"
	redisstore "github.com/hyperscale-stack/security/saml/sp/store/redis"
	"github.com/hyperscale-stack/security/saml/sp/storetest"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newStore returns a store over a private miniredis (pure Go, embedded Lua).
func newStore(t *testing.T, opts ...redisstore.Option) (*redisstore.Store, *miniredis.Miniredis) {
	t.Helper()

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	store, err := redisstore.New(client, opts...)
	require.NoError(t, err)

	return store, mr
}

// TestRedisStoreConformance runs the shared storage contract, races
// included, against the Lua scripts.
func TestRedisStoreConformance(t *testing.T) {
	t.Parallel()

	storetest.RunConformance(t, func() samlsp.Storage {
		store, _ := newStore(t)

		return store
	})
}

func TestNewRejectsNilClient(t *testing.T) {
	t.Parallel()

	_, err := redisstore.New(nil)
	require.Error(t, err)
}

func key(label string) string {
	sum := sha256.Sum256([]byte(label))

	return hex.EncodeToString(sum[:])
}

func record(label string, ttl time.Duration) *samlsp.TransactionRecord {
	return &samlsp.TransactionRecord{
		ID: key("tx/" + label), BindingHash: key("b/" + label), Payload: `{"v":1,"app":"/é"}`,
		ExpiresAt: time.Now().Add(ttl).Truncate(time.Second),
	}
}

func TestKeyLayoutAndPrefix(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, mr := newStore(t, redisstore.WithKeyPrefix("tenant1:"))
	rec := record("layout", time.Hour)

	require.NoError(t, store.SaveTransaction(ctx, rec))
	require.NoError(t, store.MarkAssertionUsed(ctx, key("a"), rec.ExpiresAt))

	assert.Equal(t, rec.BindingHash, mr.HGet("tenant1:tx:"+rec.ID, "b"))
	assert.Equal(t, rec.Payload, mr.HGet("tenant1:tx:"+rec.ID, "p"))
	assert.True(t, mr.Exists("tenant1:as:"+key("a")))
	assert.InDelta(t, time.Hour, mr.TTL("tenant1:tx:"+rec.ID), float64(2*time.Second), "expires at the transaction expiry")

	// Another prefix on the same server sees nothing.
	other, err := redisstore.New(redis.NewClient(&redis.Options{Addr: mr.Addr()}))
	require.NoError(t, err)

	_, err = other.LookupTransaction(ctx, rec.ID)
	require.ErrorIs(t, err, samlsp.ErrTransactionNotFound)
	require.NoError(t, other.MarkAssertionUsed(ctx, key("a"), rec.ExpiresAt))
}

func TestExpiryPurges(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, mr := newStore(t)

	rec := record("ttl", 10*time.Second)
	require.NoError(t, store.SaveTransaction(ctx, rec))
	require.NoError(t, store.MarkAssertionUsed(ctx, key("a"), rec.ExpiresAt))

	mr.FastForward(5 * time.Second)

	_, err := store.LookupTransaction(ctx, rec.ID)
	require.NoError(t, err, "retained before its expiry")
	require.ErrorIs(t, store.MarkAssertionUsed(ctx, key("a"), rec.ExpiresAt), samlsp.ErrAssertionReplayed)

	require.NoError(t, store.ConsumeTransaction(ctx, rec.ID, rec.BindingHash))
	assert.InDelta(t, 5*time.Second, mr.TTL("samlsp:tx:"+rec.ID), float64(2*time.Second), "consuming keeps the expiry")

	mr.FastForward(6 * time.Second)

	_, err = store.LookupTransaction(ctx, rec.ID)
	require.ErrorIs(t, err, samlsp.ErrTransactionNotFound, "purged after its expiry")
	require.NoError(t, store.MarkAssertionUsed(ctx, key("a"), time.Now().Add(time.Hour).Truncate(time.Second)),
		"a replay entry may be purged after its expiry")
}

// resendHook runs the matching script twice, as go-redis does when a reply
// is lost: the second run must recognize the first one's write.
type resendHook struct {
	key     string
	resends atomic.Int32
}

func (h *resendHook) DialHook(next redis.DialHook) redis.DialHook { return next }

func (h *resendHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func (h *resendHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		args := cmd.Args()
		if (cmd.Name() == "evalsha" || cmd.Name() == "eval") && len(args) > 3 && args[3] == h.key {
			if err := next(ctx, cmd); err != nil {
				return err // NOSCRIPT: go-redis falls back to EVAL
			}

			h.resends.Add(1)
		}

		return next(ctx, cmd)
	}
}

func TestResentScriptsAreIdempotent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	rec := record("resend", time.Hour)

	for _, target := range []string{"samlsp:tx:" + rec.ID, "samlsp:as:" + key("a")} {
		hook := &resendHook{key: target}
		mr := miniredis.RunT(t)
		client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		client.AddHook(hook)
		t.Cleanup(func() { _ = client.Close() })

		store, err := redisstore.New(client)
		require.NoError(t, err)

		require.NoError(t, store.SaveTransaction(ctx, rec), "a resent save is not a duplicate")
		require.NoError(t, store.ConsumeTransaction(ctx, rec.ID, rec.BindingHash), "a resent consumption is not a replay")
		require.NoError(t, store.MarkAssertionUsed(ctx, key("a"), rec.ExpiresAt), "a resent mark is not a replay")
		assert.Positive(t, hook.resends.Load())

		require.ErrorIs(t, store.ConsumeTransaction(ctx, rec.ID, rec.BindingHash), samlsp.ErrTransactionConsumed)
		require.ErrorIs(t, store.MarkAssertionUsed(ctx, key("a"), rec.ExpiresAt), samlsp.ErrAssertionReplayed)
	}
}

func TestBackendFailuresAreNotRejections(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, mr := newStore(t)
	rec := record("fail", time.Hour)

	// A key of the wrong type makes every command fail.
	require.NoError(t, mr.Set("samlsp:tx:"+rec.ID, "string"))
	require.NoError(t, mr.Set("samlsp:as:"+key("a"), "x"))
	mr.Lpush("samlsp:as:"+key("list"), "x")

	_, lookupErr := store.LookupTransaction(ctx, rec.ID)
	errs := []error{
		store.SaveTransaction(ctx, rec),
		store.ConsumeTransaction(ctx, rec.ID, rec.BindingHash),
		store.MarkAssertionUsed(ctx, key("list"), rec.ExpiresAt),
		lookupErr,
	}

	for _, err := range errs {
		require.Error(t, err)
		require.NotErrorIs(t, err, samlsp.ErrRejected)
	}

	mr.Close()

	require.Error(t, store.SaveTransaction(ctx, record("closed", time.Hour)))
	require.Error(t, store.MarkAssertionUsed(ctx, key("closed"), rec.ExpiresAt))
	require.Error(t, store.ConsumeTransaction(ctx, rec.ID, rec.BindingHash))
}

func TestCorruptExpiry(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, mr := newStore(t)
	rec := record("corrupt", time.Hour)

	mr.HSet("samlsp:tx:"+rec.ID, "b", rec.BindingHash, "p", rec.Payload, "e", "soon")

	_, err := store.LookupTransaction(ctx, rec.ID)
	require.Error(t, err)
	require.NotErrorIs(t, err, samlsp.ErrRejected)

	// A partial hash is an unknown transaction.
	mr.HSet("samlsp:tx:"+key("partial"), "b", rec.BindingHash)

	_, err = store.LookupTransaction(ctx, key("partial"))
	require.ErrorIs(t, err, samlsp.ErrTransactionNotFound)
}

func TestInvalidInputsNeverReachRedis(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, _ := newStore(t)

	require.ErrorIs(t, store.SaveTransaction(ctx, &samlsp.TransactionRecord{}), samlsp.ErrInvalidStoreRecord)

	_, err := store.LookupTransaction(ctx, "x")
	require.ErrorIs(t, err, samlsp.ErrInvalidStoreRecord)
	require.ErrorIs(t, store.ConsumeTransaction(ctx, "x", key("b")), samlsp.ErrInvalidStoreRecord)
	require.ErrorIs(t, store.ConsumeTransaction(ctx, key("x"), "b"), samlsp.ErrInvalidStoreRecord)
	require.ErrorIs(t, store.MarkAssertionUsed(ctx, "k", time.Now()), samlsp.ErrInvalidStoreRecord)
	require.ErrorIs(t, store.MarkAssertionUsed(ctx, key("k"), time.Time{}), samlsp.ErrInvalidStoreRecord)

	assert.False(t, errors.Is(nil, samlsp.ErrRejected))
}

// replyHook replaces every script reply with an unknown value, as a
// misconfigured proxy or a script version mismatch would.
type replyHook struct{}

func (replyHook) DialHook(next redis.DialHook) redis.DialHook { return next }

func (replyHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func (replyHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		err := next(ctx, cmd)

		if c, ok := cmd.(*redis.Cmd); ok && err == nil && (cmd.Name() == "evalsha" || cmd.Name() == "eval") {
			c.SetVal("surprise")
		}

		return err
	}
}

func TestUnexpectedScriptRepliesAreNotRejections(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	client.AddHook(replyHook{})
	t.Cleanup(func() { _ = client.Close() })

	store, err := redisstore.New(client)
	require.NoError(t, err)

	rec := record("surprise", time.Hour)

	for _, err := range []error{
		store.SaveTransaction(ctx, rec),
		store.ConsumeTransaction(ctx, rec.ID, rec.BindingHash),
		store.MarkAssertionUsed(ctx, key("a"), rec.ExpiresAt),
	} {
		require.ErrorContains(t, err, "unexpected reply")
		require.NotErrorIs(t, err, samlsp.ErrRejected, "an unknown reply is never mistaken for a decision")
	}
}
