// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package redisstore_test

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/hyperscale-stack/security/oauth2"
	redisstore "github.com/hyperscale-stack/security/oauth2/store/redis"
	"github.com/hyperscale-stack/security/oauth2/storetest"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The payloads a store wrote before codes and tokens recorded their issuer
// and extension data (#83).
const (
	legacyCodePayload = `{"client_id":"c","subject":"s","redirect_uri":"https://app.example/cb","scope":"r",` +
		`"code_challenge":"","code_challenge_method":"","nonce":"","issued_at":0,"expires_at":0}`
	legacyAccessPayload = `{"client_id":"c","subject":"s","scope":"r","family_id":"fam-legacy",` +
		`"audience":"api","issued_at":0,"expires_at":0}`
	legacyRefreshPayload = `{"client_id":"c","subject":"s","scope":"r","family_id":"fam-legacy",` +
		`"consumed":false,"issued_at":0,"expires_at":0}`
	// nullContextRefreshPayload carries explicit nulls: on a real Redis
	// cjson decodes them as a truthy userdata, which the rotation script
	// must read as "", like an absent field.
	nullContextRefreshPayload = `{"client_id":"c","subject":"s","scope":"r","family_id":"fam-legacy",` +
		`"consumed":false,"issued_at":0,"expires_at":0,"issuer":null,"extension_data":null}`
)

// envRedisAddr names the variable holding the address of a disposable
// Redis server (e.g. 127.0.0.1:6379) for the real-server tests. They are
// opt-in: a real-server case skips when the variable is unset. CI sets it
// (scripts/test-backends.sh) and fails on any skip.
const envRedisAddr = "OAUTH2_TEST_REDIS_ADDR"

// contextBackend is a Redis server the legacy-payload tests write raw
// payloads to: miniredis always, and the real server envRedisAddr names —
// cjson decodes a JSON null as nil on miniredis, as a truthy userdata on a
// real Redis. The real server is listed even when the variable is unset,
// without a client: its cases then skip (skipIfUnset).
type contextBackend struct {
	name   string
	client *redis.Client
	store  *redisstore.Store
	prefix string
}

// skipIfUnset skips t when b is the real server and envRedisAddr is unset.
func (b contextBackend) skipIfUnset(t *testing.T) {
	t.Helper()

	if b.client == nil {
		t.Skipf("set %s to run against a real Redis (opt-in)", envRedisAddr)
	}
}

// TestContextBackendsListTheRealServer: the real Redis is listed whether
// or not its variable is set, so that an unset or renamed variable shows
// as skipped cases — which the CI job of the real backends refuses
// (scripts/test-backends.sh) — instead of cases that silently vanish.
func TestContextBackendsListTheRealServer(t *testing.T) {
	t.Setenv(envRedisAddr, "")

	var names []string
	for _, b := range contextBackends(t) {
		names = append(names, b.name)
	}

	assert.Equal(t, []string{"miniredis", "redis"}, names)
}

// contextBackends returns the servers to run a legacy-payload test on.
func contextBackends(t *testing.T) []contextBackend {
	t.Helper()

	mr := miniredis.RunT(t)
	local := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = local.Close() })

	localStore, err := redisstore.New(local)
	require.NoError(t, err)

	backends := []contextBackend{{name: "miniredis", client: local, store: localStore, prefix: "oauth2:"}}

	addr := os.Getenv(envRedisAddr)
	if addr == "" {
		return append(backends, contextBackend{name: "redis"})
	}

	remote := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() { _ = remote.Close() })

	prefix := fmt.Sprintf("oauth2-legacy-%d-%s:", time.Now().UnixNano(), t.Name())
	t.Cleanup(func() { deleteKeys(remote, prefix) })

	remoteStore, err := redisstore.New(remote, redisstore.WithKeyPrefix(prefix))
	require.NoError(t, err)

	return append(backends, contextBackend{name: "redis", client: remote, store: remoteStore, prefix: prefix})
}

// set writes the raw payload of key, under the backend's prefix, for a minute.
func (b contextBackend) set(t *testing.T, key, payload string) {
	t.Helper()

	require.NoError(t, b.client.Set(t.Context(), b.prefix+key, payload, time.Minute).Err())
}

// exists reports whether key, under the backend's prefix, exists.
func (b contextBackend) exists(t *testing.T, key string) bool {
	t.Helper()

	n, err := b.client.Exists(t.Context(), b.prefix+key).Result()
	require.NoError(t, err)

	return n == 1
}

// TestRedisLegacyPayloadsReadEmptyContext reads records written before #83:
// the code — consumed, then replayed through the script that re-encodes
// it — and both tokens come back with an empty issuer and extension data.
func TestRedisLegacyPayloadsReadEmptyContext(t *testing.T) {
	t.Parallel()

	for _, b := range contextBackends(t) {
		t.Run(b.name, func(t *testing.T) {
			b.skipIfUnset(t)

			ctx := t.Context()

			b.set(t, "code:legacy", legacyCodePayload)
			b.set(t, "fam:fam-legacy", "active")
			b.set(t, "at:at-legacy", legacyAccessPayload)
			b.set(t, "rt:rt-legacy", legacyRefreshPayload)

			code, err := b.store.ConsumeAuthorizationCode(ctx, "legacy")
			require.NoError(t, err)
			assert.Empty(t, code.Issuer)
			assert.Empty(t, code.ExtensionData)
			assert.False(t, code.RedirectURIOmitted, "a legacy code keeps requiring redirect_uri")

			_, err = b.store.ConsumeAuthorizationCode(ctx, "legacy")

			var replay *oauth2.CodeReplayError

			require.ErrorAs(t, err, &replay)
			assert.Empty(t, replay.Record.Issuer)
			assert.Empty(t, replay.Record.ExtensionData)
			assert.False(t, replay.Record.RedirectURIOmitted)

			at, err := b.store.LookupAccessToken(ctx, "at-legacy")
			require.NoError(t, err)
			assert.Empty(t, at.Issuer)
			assert.Empty(t, at.ExtensionData)

			rt, err := b.store.LookupRefreshToken(ctx, "rt-legacy")
			require.NoError(t, err)
			assert.Empty(t, rt.Issuer)
			assert.Empty(t, rt.ExtensionData)
			assert.True(t, rt.FamilyIssuedAt.IsZero(), "a legacy refresh token has no recorded family start")
		})
	}
}

// legacyRotation is the pair a rotation of the legacy refresh token issues.
func legacyRotation(name, data string) *oauth2.TokenPair {
	now := time.Now()

	return &oauth2.TokenPair{
		Access: oauth2.AccessToken{
			TokenHash: "at-" + name, ClientID: "c", Subject: "s", Scope: "r", FamilyID: "fam-legacy",
			IssuedAt: now, ExpiresAt: now.Add(time.Hour), ExtensionData: data,
		},
		Refresh: &oauth2.RefreshToken{
			TokenHash: "rt-" + name, ClientID: "c", Subject: "s", Scope: "r", FamilyID: "fam-legacy",
			IssuedAt: now, ExpiresAt: now.Add(time.Hour), ExtensionData: data,
		},
	}
}

// TestRedisRotationReadsMissingContextAsEmpty rotates a refresh token
// whose payload has no grant context — absent or null fields: the script
// takes it for an empty one, refusing a replacement that carries another
// context and accepting one that carries none. Run against a real Redis
// (OAUTH2_TEST_REDIS_ADDR), the null case exercises cjson's userdata null.
func TestRedisRotationReadsMissingContextAsEmpty(t *testing.T) {
	t.Parallel()

	for _, b := range contextBackends(t) {
		for name, payload := range map[string]string{"absent": legacyRefreshPayload, "null": nullContextRefreshPayload} {
			t.Run(b.name+"/"+name, func(t *testing.T) {
				b.skipIfUnset(t)

				ctx := t.Context()
				key := "rt-legacy-" + name

				b.set(t, "fam:fam-legacy", "active")
				b.set(t, "rt:"+key, payload)

				rewritten := legacyRotation("rewritten-"+name, "rewritten")
				err := b.store.RotateRefreshToken(ctx, key, rewritten)
				assert.Equal(t, oauth2.CodeInvalidRequest, oauth2.IsCode(err))
				assert.False(t, b.exists(t, "rt:"+rewritten.Refresh.TokenHash), "nothing written")
				assert.False(t, b.exists(t, "at:"+rewritten.Access.TokenHash), "nothing written")

				next := legacyRotation("next-"+name, "")
				require.NoError(t, b.store.RotateRefreshToken(ctx, key, next), "rotation keeping the empty context")

				stored, err := b.store.LookupRefreshToken(ctx, next.Refresh.TokenHash)
				require.NoError(t, err)
				assert.False(t, stored.Consumed)
			})
		}
	}
}

// TestRedisStoreConformanceRealServer runs the shared suite against a real
// Redis — cjson's encoder and decoder differ from miniredis' Lua ones on
// the re-encoded replay and rotation payloads. Opt-in (envRedisAddr, set
// by CI): every run uses its own key prefix and deletes its keys.
func TestRedisStoreConformanceRealServer(t *testing.T) {
	addr := os.Getenv(envRedisAddr)
	if addr == "" {
		t.Skipf("set %s to run the conformance suite against a real Redis (opt-in)", envRedisAddr)
	}

	client := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() { _ = client.Close() })
	require.NoError(t, client.Ping(context.Background()).Err())

	var run atomic.Int64

	base := fmt.Sprintf("oauth2-conformance-%d:", time.Now().UnixNano())

	storetest.RunConformance(t, func() oauth2.Storage {
		prefix := fmt.Sprintf("%s%d:", base, run.Add(1))

		t.Cleanup(func() { deleteKeys(client, prefix) })

		store, err := redisstore.New(client, redisstore.WithKeyPrefix(prefix))
		require.NoError(t, err)

		return store
	})
}

// deleteKeys removes every key under prefix.
func deleteKeys(client *redis.Client, prefix string) {
	ctx := context.Background()

	iter := client.Scan(ctx, 0, prefix+"*", 100).Iterator()
	for iter.Next(ctx) {
		_ = client.Del(ctx, iter.Val()).Err()
	}
}
