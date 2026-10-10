// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package redisstore_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/hyperscale-stack/security/oauth2"
	redisstore "github.com/hyperscale-stack/security/oauth2/store/redis"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedisStoreRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	store := newRedisStore(t)
	ctx := context.Background()
	tooLong := strings.Repeat("f", oauth2.MaxFamilyIDLength+1)
	bare := &oauth2.TokenPair{Access: oauth2.AccessToken{TokenHash: "h", FamilyID: "f"}}

	require.Error(t, store.SaveAuthorizationCode(ctx, &oauth2.AuthorizationCode{}))

	for _, err := range []error{
		store.SaveTokenPair(ctx, &oauth2.TokenPair{}),
		store.SaveTokenPair(ctx, nil),
		store.RotateRefreshToken(ctx, "h", nil),
		store.RotateRefreshToken(ctx, "h", bare),
		store.RevokeRefreshFamily(ctx, ""),
		store.RevokeRefreshFamily(ctx, tooLong),
	} {
		assert.Equal(t, oauth2.CodeInvalidRequest, oauth2.IsCode(err), "%v", err)
	}
}

// TestRedisStoreReportsBackendErrors closes the miniredis server so every
// command fails, exercising the store's error-return branches.
func TestRedisStoreReportsBackendErrors(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	// No retries: every command fails anyway, and retrying a dead server
	// only slows the test down.
	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
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

	require.Error(t, store.SaveTokenPair(ctx, testPair("h", "f", time.Minute)))
	require.Error(t, store.SaveTokenPair(ctx, &oauth2.TokenPair{Access: oauth2.AccessToken{
		TokenHash: "h", ExpiresAt: now.Add(time.Minute),
	}}))

	_, err = store.LookupAccessToken(ctx, "h")
	require.Error(t, err)

	require.Error(t, store.RevokeAccessToken(ctx, "h"))

	_, err = store.LookupRefreshToken(ctx, "h")
	require.Error(t, err)

	require.Error(t, store.RotateRefreshToken(ctx, "h", testPair("next", "f", time.Minute)))
	require.ErrorIs(t, store.RevokeRefreshFamily(ctx, "f"), oauth2.ErrTokenFamilyRevocationFailed)
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

	// A corrupt old token aborts the rotation before it writes anything.
	next := testPair("after-bad", "f", time.Hour)
	require.Error(t, store.RotateRefreshToken(ctx, "bad", next))
	assert.False(t, mr.Exists("oauth2:rt:rt-after-bad"))
	assert.False(t, mr.Exists("oauth2:at:at-after-bad"))
	assert.False(t, mr.Exists("oauth2:fam:f"))
}

// TestRedisStoreConsumeUnknownCode covers the "code already used / absent"
// branch of the consume script.
func TestRedisStoreConsumeUnknownCode(t *testing.T) {
	t.Parallel()

	store := newRedisStore(t)

	_, err := store.ConsumeAuthorizationCode(context.Background(), "never-saved")
	require.ErrorIs(t, err, oauth2.ErrCodeAlreadyUsed)
}

// TestRedisStoreSavePastExpiryClampsTTL saves a token already past its
// expiry; ttlUntil must clamp the key TTL to the 1-second floor.
func TestRedisStoreSavePastExpiryClampsTTL(t *testing.T) {
	t.Parallel()

	store := newRedisStore(t)
	ctx := context.Background()

	at := oauth2.AccessToken{
		TokenHash: "expired", ClientID: "c", Subject: "s",
		IssuedAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(-time.Minute),
	}
	require.NoError(t, store.SaveTokenPair(ctx, &oauth2.TokenPair{Access: at}))

	got, err := store.LookupAccessToken(ctx, "expired")
	require.NoError(t, err)
	assert.Equal(t, "c", got.ClientID)
}
