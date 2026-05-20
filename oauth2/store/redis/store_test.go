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
	"github.com/hyperscale-stack/security/oauth2/storetest"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

// newRedisStore spins up an isolated miniredis server (pure-Go, no Docker)
// and returns a Store wired to it. miniredis embeds a Lua interpreter with
// cjson, so the consume-code and rotate-refresh scripts run exactly as on
// a real Redis.
func newRedisStore(t *testing.T) oauth2.Storage {
	t.Helper()

	mr := miniredis.RunT(t)

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	store, err := redisstore.New(client)
	require.NoError(t, err)

	return store
}

// TestRedisStoreConformance runs the shared storage contract against the
// Redis implementation. The same 11-case suite the memory and SQL stores
// pass — concurrency races included — exercising the Lua-script atomicity.
func TestRedisStoreConformance(t *testing.T) {
	t.Parallel()

	storetest.RunConformance(t, func() oauth2.Storage {
		return newRedisStore(t)
	})
}

// TestNewRejectsNilClient checks the constructor guard.
func TestNewRejectsNilClient(t *testing.T) {
	t.Parallel()

	_, err := redisstore.New(nil)
	require.Error(t, err)
}

// TestKeyPrefixIsHonored verifies WithKeyPrefix namespaces the keys: two
// stores with different prefixes on the same Redis do not see each other.
func TestKeyPrefixIsHonored(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	a, err := redisstore.New(client, redisstore.WithKeyPrefix("tenant-a:"))
	require.NoError(t, err)
	b, err := redisstore.New(client, redisstore.WithKeyPrefix("tenant-b:"))
	require.NoError(t, err)

	now := time.Now()
	code := &oauth2.AuthorizationCode{
		Code: "raw", CodeHash: "shared-hash", ClientID: "c", Subject: "s",
		RedirectURI: "https://x", Scope: "read",
		IssuedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	require.NoError(t, a.SaveAuthorizationCode(context.Background(), code))

	// Tenant B must not see tenant A's code despite the identical hash.
	_, err = b.ConsumeAuthorizationCode(context.Background(), "shared-hash")
	require.Error(t, err, "key prefixes must isolate tenants")

	// Tenant A still consumes it fine.
	got, err := a.ConsumeAuthorizationCode(context.Background(), "shared-hash")
	require.NoError(t, err)
	require.Equal(t, "c", got.ClientID)
}
