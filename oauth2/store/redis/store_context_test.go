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

// TestRedisLegacyPayloadsReadEmptyContext reads records written before #83:
// the code — consumed, then replayed through the script that re-encodes
// it — and both tokens come back with an empty issuer and extension data.
func TestRedisLegacyPayloadsReadEmptyContext(t *testing.T) {
	t.Parallel()

	store, _, mr := hookedStores(t, &scriptHook{})
	ctx := t.Context()

	require.NoError(t, mr.Set(codeKey("legacy"), legacyCodePayload))
	mr.SetTTL(codeKey("legacy"), time.Minute)
	require.NoError(t, mr.Set("oauth2:fam:fam-legacy", "active"))
	require.NoError(t, mr.Set("oauth2:at:at-legacy", legacyAccessPayload))
	require.NoError(t, mr.Set("oauth2:rt:rt-legacy", legacyRefreshPayload))

	code, err := store.ConsumeAuthorizationCode(ctx, "legacy")
	require.NoError(t, err)
	assert.Empty(t, code.Issuer)
	assert.Empty(t, code.ExtensionData)

	_, err = store.ConsumeAuthorizationCode(ctx, "legacy")

	var replay *oauth2.CodeReplayError

	require.ErrorAs(t, err, &replay)
	assert.Empty(t, replay.Record.Issuer)
	assert.Empty(t, replay.Record.ExtensionData)

	at, err := store.LookupAccessToken(ctx, "at-legacy")
	require.NoError(t, err)
	assert.Empty(t, at.Issuer)
	assert.Empty(t, at.ExtensionData)

	rt, err := store.LookupRefreshToken(ctx, "rt-legacy")
	require.NoError(t, err)
	assert.Empty(t, rt.Issuer)
	assert.Empty(t, rt.ExtensionData)
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
// context and accepting one that carries none.
func TestRedisRotationReadsMissingContextAsEmpty(t *testing.T) {
	t.Parallel()

	for name, payload := range map[string]string{"absent": legacyRefreshPayload, "null": nullContextRefreshPayload} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			store, _, mr := hookedStores(t, &scriptHook{})
			ctx := t.Context()

			require.NoError(t, mr.Set("oauth2:fam:fam-legacy", "active"))
			require.NoError(t, mr.Set("oauth2:rt:rt-legacy", payload))

			err := store.RotateRefreshToken(ctx, "rt-legacy", legacyRotation("rewritten", "rewritten"))
			assert.Equal(t, oauth2.CodeInvalidRequest, oauth2.IsCode(err))
			assert.False(t, mr.Exists("oauth2:rt:rt-rewritten"), "nothing written")
			assert.False(t, mr.Exists("oauth2:at:at-rewritten"), "nothing written")

			require.NoError(t, store.RotateRefreshToken(ctx, "rt-legacy", legacyRotation("next", "")))

			next, err := store.LookupRefreshToken(ctx, "rt-next")
			require.NoError(t, err)
			assert.False(t, next.Consumed)
		})
	}
}

// TestRedisStoreConformanceRealServer runs the shared suite against a real
// Redis — cjson's encoder and decoder differ from miniredis' Lua ones on
// the re-encoded replay and rotation payloads. Opt-in: set
// OAUTH2_TEST_REDIS_ADDR (e.g. 127.0.0.1:6379) to a disposable server;
// every run uses its own key prefix and deletes its keys.
func TestRedisStoreConformanceRealServer(t *testing.T) {
	addr := os.Getenv("OAUTH2_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("set OAUTH2_TEST_REDIS_ADDR to run the conformance suite against a real Redis")
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
