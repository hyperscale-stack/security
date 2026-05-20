// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package redisstore_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/hyperscale-stack/security/oauth2"
	redisstore "github.com/hyperscale-stack/security/oauth2/store/redis"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedisStoreRejectsEmptyHashes(t *testing.T) {
	t.Parallel()

	store := newRedisStore(t)
	ctx := context.Background()

	require.Error(t, store.SaveAuthorizationCode(ctx, &oauth2.AuthorizationCode{}))
	require.Error(t, store.SaveAccessToken(ctx, &oauth2.AccessToken{}))
	require.Error(t, store.SaveRefreshToken(ctx, &oauth2.RefreshToken{}))
}

// TestRedisStoreReportsBackendErrors closes the miniredis server so every
// command fails, exercising the store's error-return branches.
func TestRedisStoreReportsBackendErrors(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	store, err := redisstore.New(client)
	require.NoError(t, err)

	mr.Close() // the backend is now unreachable

	ctx := context.Background()
	now := time.Now()

	code := &oauth2.AuthorizationCode{
		CodeHash: "h", ExpiresAt: now.Add(time.Minute),
	}
	require.Error(t, store.SaveAuthorizationCode(ctx, code))

	_, err = store.ConsumeAuthorizationCode(ctx, "h")
	require.Error(t, err)

	at := &oauth2.AccessToken{TokenHash: "h", FamilyID: "f", ExpiresAt: now.Add(time.Minute)}
	require.Error(t, store.SaveAccessToken(ctx, at))

	_, err = store.LookupAccessToken(ctx, "h")
	require.Error(t, err)

	require.Error(t, store.RevokeAccessToken(ctx, "h"))

	rt := &oauth2.RefreshToken{TokenHash: "h", FamilyID: "f", ExpiresAt: now.Add(time.Minute)}
	require.Error(t, store.SaveRefreshToken(ctx, rt))

	_, err = store.LookupRefreshToken(ctx, "h")
	require.Error(t, err)

	require.Error(t, store.RotateRefreshToken(ctx, "h", rt))
	require.Error(t, store.RevokeRefreshFamily(ctx, "f"))
}

// TestRedisStoreDecodeErrors injects corrupt JSON directly into Redis and
// checks the decode-error branches.
func TestRedisStoreDecodeErrors(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	store, err := redisstore.New(client)
	require.NoError(t, err)

	ctx := context.Background()

	require.NoError(t, mr.Set("oauth2:code:bad", "{not-json"))
	_, err = store.ConsumeAuthorizationCode(ctx, "bad")
	require.Error(t, err)

	require.NoError(t, mr.Set("oauth2:at:bad", "{not-json"))
	_, err = store.LookupAccessToken(ctx, "bad")
	require.Error(t, err)

	require.NoError(t, mr.Set("oauth2:rt:bad", "{not-json"))
	_, err = store.LookupRefreshToken(ctx, "bad")
	require.Error(t, err)
}

// TestRedisStoreConsumeUnknownCode covers the "code already used / absent"
// branch of the consume script.
func TestRedisStoreConsumeUnknownCode(t *testing.T) {
	t.Parallel()

	store := newRedisStore(t)

	_, err := store.ConsumeAuthorizationCode(context.Background(), "never-saved")
	require.ErrorIs(t, err, oauth2.ErrCodeAlreadyUsed)
}

// TestRedisStoreRotateUnknownToken covers the script's "notfound" branch.
func TestRedisStoreRotateUnknownToken(t *testing.T) {
	t.Parallel()

	store := newRedisStore(t)

	err := store.RotateRefreshToken(context.Background(), "never-saved", &oauth2.RefreshToken{
		TokenHash: "new", FamilyID: "fam", ExpiresAt: time.Now().Add(time.Hour),
	})
	require.Error(t, err)
}

// TestRedisStoreRevokeFamilyMarksRefreshTokens checks the family-revocation
// path: every refresh token of the family ends up consumed.
func TestRedisStoreRevokeFamilyMarksRefreshTokens(t *testing.T) {
	t.Parallel()

	store := newRedisStore(t)
	ctx := context.Background()
	now := time.Now()

	rt := &oauth2.RefreshToken{
		Token: "raw", TokenHash: "rt-hash", ClientID: "c", Subject: "s",
		Scope: "read", FamilyID: "fam-1", IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	require.NoError(t, store.SaveRefreshToken(ctx, rt))

	require.NoError(t, store.RevokeRefreshFamily(ctx, "fam-1"))

	got, err := store.LookupRefreshToken(ctx, "rt-hash")
	require.NoError(t, err)
	assert.True(t, got.Consumed, "family revocation must mark the refresh token consumed")

	// Revoking again is idempotent — the token is already consumed.
	require.NoError(t, store.RevokeRefreshFamily(ctx, "fam-1"))
}

// TestRedisStoreRevokeFamilyWithCorruptMember exercises the markConsumed
// decode-error branch.
func TestRedisStoreRevokeFamilyWithCorruptMember(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	store, err := redisstore.New(client)
	require.NoError(t, err)

	// A family set referencing a refresh token whose payload is corrupt.
	_, err = mr.SAdd("oauth2:famrt:fam-x", "corrupt-hash")
	require.NoError(t, err)
	require.NoError(t, mr.Set("oauth2:rt:corrupt-hash", "{not-json"))

	require.Error(t, store.RevokeRefreshFamily(context.Background(), "fam-x"))
}

// TestRedisStoreSavePastExpiryClampsTTL saves a token already past its
// expiry; ttlUntil must clamp the key TTL to the 1-second floor.
func TestRedisStoreSavePastExpiryClampsTTL(t *testing.T) {
	t.Parallel()

	store := newRedisStore(t)
	ctx := context.Background()

	at := &oauth2.AccessToken{
		TokenHash: "expired", ClientID: "c", Subject: "s",
		IssuedAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(-time.Minute),
	}
	require.NoError(t, store.SaveAccessToken(ctx, at))

	got, err := store.LookupAccessToken(ctx, "expired")
	require.NoError(t, err)
	assert.Equal(t, "c", got.ClientID)
}
