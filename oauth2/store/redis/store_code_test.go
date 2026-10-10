// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package redisstore_test

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/hyperscale-stack/security/oauth2"
	redisstore "github.com/hyperscale-stack/security/oauth2/store/redis"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// codeKey is the key of an authorization code under the default prefix.
func codeKey(hash string) string { return "oauth2:code:" + hash }

// testCode returns an authorization code stored under hash that expires
// after ttl.
func testCode(hash string, ttl time.Duration) *oauth2.AuthorizationCode {
	now := time.Now()

	return &oauth2.AuthorizationCode{
		Code: "raw-" + hash, CodeHash: hash, ClientID: "c", Subject: "s",
		RedirectURI: "https://app.example/cb", Scope: "r",
		CodeChallenge: "challenge", CodeChallengeMethod: "S256", Nonce: "n",
		IssuedAt: now, ExpiresAt: now.Add(ttl),
	}
}

// requireCodeReplay asserts that got and err report a replay of the code
// stored under hash: no code, and the retained record in the error.
func requireCodeReplay(t *testing.T, got *oauth2.AuthorizationCode, err error, hash string) {
	t.Helper()

	assert.Nil(t, got)

	var replay *oauth2.CodeReplayError

	require.ErrorAs(t, err, &replay)
	require.NotNil(t, replay.Record)
	assert.Equal(t, hash, replay.Record.CodeHash)
	assert.Equal(t, "c", replay.Record.ClientID)
}

// TestRedisConsumedCodeKeepsItsTTL: consuming a code flags its key without
// touching its TTL, so the record stays recognizable exactly until the code
// expires, and no longer.
func TestRedisConsumedCodeKeepsItsTTL(t *testing.T) {
	t.Parallel()

	store, _, mr := hookedStores(t, &scriptHook{})
	ctx := t.Context()

	require.NoError(t, store.SaveAuthorizationCode(ctx, testCode("ttl", 10*time.Minute)))

	mr.FastForward(4 * time.Minute)

	got, err := store.ConsumeAuthorizationCode(ctx, "ttl")
	require.NoError(t, err)
	assert.Equal(t, "c", got.ClientID)
	assert.InDelta(t, 6*time.Minute, mr.TTL(codeKey("ttl")), float64(time.Second), "neither reset nor cleared")

	got, err = store.ConsumeAuthorizationCode(ctx, "ttl")
	requireCodeReplay(t, got, err, "ttl")

	mr.FastForward(7 * time.Minute)
	assert.False(t, mr.Exists(codeKey("ttl")), "the record expires with the code")

	got, err = store.ConsumeAuthorizationCode(ctx, "ttl")
	assert.Nil(t, got)
	require.ErrorIs(t, err, oauth2.ErrCodeAlreadyUsed)

	var replay *oauth2.CodeReplayError

	assert.NotErrorAs(t, err, &replay, "an expired record reads as an unknown code")
}

// TestRedisCodePayloadWithoutFlagIsConsumable covers payloads without a
// consumed flag — written before the flag existed — and with a null one,
// which cjson decodes as a truthy value: both are unconsumed codes.
func TestRedisCodePayloadWithoutFlagIsConsumable(t *testing.T) {
	t.Parallel()

	cases := []struct{ name, payload string }{
		{"no flag", `{"client_id":"c","subject":"s","redirect_uri":"https://app.example/cb","scope":"r",` +
			`"code_challenge":"","code_challenge_method":"","nonce":"","issued_at":0,"expires_at":0}`},
		{"null flag", `{"client_id":"c","subject":"s","redirect_uri":"https://app.example/cb","scope":"r",` +
			`"code_challenge":"","code_challenge_method":"","nonce":"","issued_at":0,"expires_at":0,` +
			`"consumed":null,"consumed_by":null}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store, _, mr := hookedStores(t, &scriptHook{})
			require.NoError(t, mr.Set(codeKey("legacy"), tc.payload))
			mr.SetTTL(codeKey("legacy"), 10*time.Minute)

			got, err := store.ConsumeAuthorizationCode(t.Context(), "legacy")
			require.NoError(t, err)
			assert.Equal(t, "https://app.example/cb", got.RedirectURI)
			assert.InDelta(t, 10*time.Minute, mr.TTL(codeKey("legacy")), float64(time.Second))

			got, err = store.ConsumeAuthorizationCode(t.Context(), "legacy")
			requireCodeReplay(t, got, err, "legacy")
		})
	}
}

// TestRedisConsumeCodeDecodeError covers a payload the script can decode
// but the store cannot: the consume fails with an error, not a code.
func TestRedisConsumeCodeDecodeError(t *testing.T) {
	t.Parallel()

	store, _, mr := hookedStores(t, &scriptHook{})
	require.NoError(t, mr.Set(codeKey("odd"), `{"issued_at":"x"}`))

	got, err := store.ConsumeAuthorizationCode(t.Context(), "odd")
	assert.Nil(t, got)
	require.ErrorContains(t, err, "redisstore: decode code")
	assert.NotErrorIs(t, err, oauth2.ErrCodeAlreadyUsed)
}

// TestRedisResentConsumeIsNotReplay runs the consume script twice, the way
// go-redis resends a command whose reply was lost: the second run finds the
// code consumed by the first, and the store must still see its own win —
// not a replay that refuses the exchange.
func TestRedisResentConsumeIsNotReplay(t *testing.T) {
	t.Parallel()

	hook := &resendHook{}
	hook.numKeys, hook.key = 1, codeKey("resent")

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	client.AddHook(hook)
	t.Cleanup(func() { _ = client.Close() })

	store, err := redisstore.New(client)
	require.NoError(t, err)

	require.NoError(t, store.SaveAuthorizationCode(t.Context(), testCode("resent", time.Minute)))

	got, err := store.ConsumeAuthorizationCode(t.Context(), "resent")
	require.NoError(t, err)
	assert.Equal(t, "c", got.ClientID)

	// Another call — another nonce — sees a replay.
	got, err = store.ConsumeAuthorizationCode(t.Context(), "resent")
	requireCodeReplay(t, got, err, "resent")
}
