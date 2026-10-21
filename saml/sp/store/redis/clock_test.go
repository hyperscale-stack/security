// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package redisstore_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	samlsp "github.com/hyperscale-stack/security/saml/sp"
	redisstore "github.com/hyperscale-stack/security/saml/sp/store/redis"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// envRedisAddr names a disposable real Redis server (scripts/test-backends.sh).
const envRedisAddr = "SAMLSP_REDIS_ADDR"

// TestKeyLifetimesIgnoreTheRedisClock: the store measures how long a key
// must live on the SP's clock and sends that duration, so the offset of
// Redis's clock plays no part. With Redis two minutes ahead, an absolute
// expiry one minute away on the SP's clock is already past for Redis: the
// replay mark would vanish as it is written, and the same assertion be
// accepted again (SAML 2.0 Profiles §4.1.4.5). With Redis behind, the keys
// would outlive their retention.
func TestKeyLifetimesIgnoreTheRedisClock(t *testing.T) {
	t.Parallel()

	for _, offset := range []time.Duration{2 * time.Minute, -2 * time.Minute} {
		t.Run(offset.String(), func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			store, mr := newStore(t)
			mr.SetTime(time.Now().Add(offset))

			mark := key("skewed mark")
			expiry := time.Now().Add(time.Minute).Truncate(time.Second)

			require.NoError(t, store.MarkAssertionUsed(ctx, mark, expiry), "first mark")
			require.ErrorIs(t, store.MarkAssertionUsed(ctx, mark, expiry), samlsp.ErrAssertionReplayed,
				"the mark is kept until its expiry on the SP's clock")
			assert.InDelta(t, time.Minute, mr.TTL("samlsp:as:"+mark), float64(2*time.Second), "the mark's lifetime")

			rec := record("skewed transaction", time.Minute)
			require.NoError(t, store.SaveTransaction(ctx, rec))

			got, err := store.LookupTransaction(ctx, rec.ID)
			require.NoError(t, err, "the transaction is kept until its expiry on the SP's clock")
			assert.Equal(t, rec.ExpiresAt.Unix(), got.ExpiresAt.Unix(), "the recorded expiry is the SP's")
			assert.InDelta(t, time.Minute, mr.TTL("samlsp:tx:"+rec.ID), float64(2*time.Second), "the transaction's lifetime")
		})
	}
}

// TestWithClockMeasuresKeyLifetimes: the lifetimes are measured on the
// clock WithClock names — the SP's samlsp.Config.Now — not on the host's.
func TestWithClockMeasuresKeyLifetimes(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	spNow := time.Now().Add(-10 * time.Minute)
	store, mr := newStore(t, redisstore.WithClock(func() time.Time { return spNow }))

	mark := key("injected clock")
	expiry := spNow.Add(time.Minute).Truncate(time.Second)

	require.NoError(t, store.MarkAssertionUsed(ctx, mark, expiry))
	require.ErrorIs(t, store.MarkAssertionUsed(ctx, mark, expiry), samlsp.ErrAssertionReplayed)
	assert.InDelta(t, expiry.Sub(spNow), mr.TTL("samlsp:as:"+mark), float64(time.Second))

	rec := record("injected clock", 0)
	rec.ExpiresAt = spNow.Add(5 * time.Minute).Truncate(time.Second)
	require.NoError(t, store.SaveTransaction(ctx, rec))
	assert.InDelta(t, rec.ExpiresAt.Sub(spNow), mr.TTL("samlsp:tx:"+rec.ID), float64(time.Second))

	// A nil clock keeps the default one.
	defaulted, mr2 := newStore(t, redisstore.WithClock(nil))
	require.NoError(t, defaulted.MarkAssertionUsed(ctx, mark, time.Now().Add(time.Minute).Truncate(time.Second)))
	assert.InDelta(t, time.Minute, mr2.TTL("samlsp:as:"+mark), float64(2*time.Second))
}

// TestPastExpiryKeepsKeysBriefly: an expiry already past on the SP's clock
// still gets a key, for a second — Redis refuses a lifetime that is not
// positive — rather than an error or no key at all.
func TestPastExpiryKeepsKeysBriefly(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, mr := newStore(t)
	past := time.Now().Add(-time.Hour).Truncate(time.Second)

	mark := key("past mark")
	require.NoError(t, store.MarkAssertionUsed(ctx, mark, past))
	assert.Equal(t, time.Second, mr.TTL("samlsp:as:"+mark))

	rec := record("past transaction", 0)
	rec.ExpiresAt = past
	require.NoError(t, store.SaveTransaction(ctx, rec))
	assert.Equal(t, time.Second, mr.TTL("samlsp:tx:"+rec.ID))
}

// TestRealRedisClockSkew runs the clock-skew check on a real server
// (SAMLSP_REDIS_ADDR): the SP's clock, injected, is set two minutes behind
// and then ahead of the Redis TIME, and every key lives the minute the SP
// asked for.
func TestRealRedisClockSkew(t *testing.T) {
	addr := os.Getenv(envRedisAddr)
	if addr == "" {
		t.Skipf("set %s to run against a real Redis (opt-in)", envRedisAddr)
	}

	ctx := context.Background()
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() { _ = rdb.Close() })

	b := make([]byte, 6)
	_, _ = rand.Read(b)
	prefix := "samlsp-skew-" + hex.EncodeToString(b) + ":"

	t.Cleanup(func() {
		keys, _ := rdb.Keys(context.Background(), prefix+"*").Result()
		if len(keys) > 0 {
			_ = rdb.Del(context.Background(), keys...).Err()
		}
	})

	redisNow, err := rdb.Time(ctx).Result()
	require.NoError(t, err)

	for _, offset := range []time.Duration{-2 * time.Minute, 2 * time.Minute} {
		spNow := redisNow.Add(offset)
		store, err := redisstore.New(rdb, redisstore.WithKeyPrefix(prefix+offset.String()+":"),
			redisstore.WithClock(func() time.Time { return spNow }))
		require.NoError(t, err)

		mark := key("real skew")
		expiry := spNow.Add(time.Minute).Truncate(time.Second)

		require.NoError(t, store.MarkAssertionUsed(ctx, mark, expiry), "first mark, SP clock %s", offset)
		require.ErrorIs(t, store.MarkAssertionUsed(ctx, mark, expiry), samlsp.ErrAssertionReplayed,
			"second mark, SP clock %s", offset)

		ttl, err := rdb.PTTL(ctx, prefix+offset.String()+":as:"+mark).Result()
		require.NoError(t, err)
		assert.InDelta(t, expiry.Sub(spNow), ttl, float64(2*time.Second), "the mark's lifetime, SP clock %s", offset)

		rec := record("real skew", 0)
		rec.ExpiresAt = spNow.Add(time.Minute).Truncate(time.Second)
		require.NoError(t, store.SaveTransaction(ctx, rec))

		_, err = store.LookupTransaction(ctx, rec.ID)
		require.NoError(t, err, "the transaction, SP clock %s", offset)

		ttl, err = rdb.PTTL(ctx, prefix+offset.String()+":tx:"+rec.ID).Result()
		require.NoError(t, err)
		assert.InDelta(t, rec.ExpiresAt.Sub(spNow), ttl, float64(2*time.Second), "the transaction's lifetime, SP clock %s", offset)
	}
}
