// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package redisstore_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	redisstore "github.com/hyperscale-stack/security/oidc/client/store/redis"
	"github.com/hyperscale-stack/security/oidc/client/storetest"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newStore starts an isolated miniredis server — pure Go, with the Lua
// interpreter and cjson of a real Redis — and returns a Store over it.
func newStore(t *testing.T, opts ...redisstore.Option) (*redisstore.Store, *miniredis.Miniredis) {
	t.Helper()

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	store, err := redisstore.New(client, opts...)
	require.NoError(t, err)

	return store, mr
}

func hash(s string) string {
	sum := sha256.Sum256([]byte(s))

	return hex.EncodeToString(sum[:])
}

func key(stateHash string) string { return "oidcclient:tx:" + stateHash }

// now is the current time in whole seconds.
func now() time.Time { return time.Unix(time.Now().Unix(), 0).UTC() }

// sample returns a valid transaction unique per seed, created at, living
// ttl.
func sample(seed string, at time.Time, ttl time.Duration) *oidcclient.Transaction {
	return &oidcclient.Transaction{
		StateHash:    hash("state-" + seed),
		BindingHash:  hash("binding-" + seed),
		ConnectionID: "acme",
		Issuer:       "https://idp.example.com/tenants/acme",
		ClientID:     "client-1",
		RedirectURI:  "https://rp.example.com/oidc/acme/callback",
		ResponseMode: oidcclient.ResponseModeFormPost,
		MaxAge:       300,
		ACRValues:    "urn:acr:gold",
		AppState:     "a\x00b <&> \U0001F512 é",
		CreatedAt:    at,
		ExpiresAt:    at.Add(ttl),
		Integrity:    hash("integrity-" + seed),
	}
}

func TestConformance(t *testing.T) {
	t.Parallel()

	storetest.RunConformance(t, func() oidcclient.TransactionStore {
		store, _ := newStore(t)

		return store
	})
}

func TestNewRejectsNilClient(t *testing.T) {
	t.Parallel()

	_, err := redisstore.New(nil)
	require.Error(t, err)
}

// TestKeyLayout pins the key and the on-wire payload the Lua script reads:
// prefix + "tx:" + state hash, a JSON object of explicit members, Unix
// seconds, and a TTL of the transaction's lifetime.
func TestKeyLayout(t *testing.T) {
	t.Parallel()

	store, mr := newStore(t)
	at := now()
	tx := sample("layout", at, 10*time.Minute)
	require.NoError(t, store.Save(t.Context(), tx))

	raw, err := mr.Get(key(tx.StateHash))
	require.NoError(t, err)

	var payload map[string]any
	require.NoError(t, json.Unmarshal([]byte(raw), &payload))
	assert.Equal(t, map[string]any{
		"binding_hash":  tx.BindingHash,
		"connection_id": "acme",
		"issuer":        "https://idp.example.com/tenants/acme",
		"client_id":     "client-1",
		"redirect_uri":  "https://rp.example.com/oidc/acme/callback",
		"response_mode": "form_post",
		"max_age":       float64(300),
		"acr_values":    "urn:acr:gold",
		"app_state":     tx.AppState,
		"created_at":    float64(at.Unix()),
		"expires_at":    float64(at.Add(10 * time.Minute).Unix()),
		"integrity":     tx.Integrity,
	}, payload)
	assert.Equal(t, 10*time.Minute, mr.TTL(key(tx.StateHash)))
}

func TestKeyPrefixIsolates(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	a, err := redisstore.New(client, redisstore.WithKeyPrefix("tenant-a:"))
	require.NoError(t, err)
	b, err := redisstore.New(client, redisstore.WithKeyPrefix("tenant-b:"))
	require.NoError(t, err)

	at := now()
	tx := sample("prefix", at, time.Minute)
	require.NoError(t, a.Save(t.Context(), tx))
	assert.True(t, mr.Exists("tenant-a:tx:"+tx.StateHash))

	_, err = b.Consume(t.Context(), tx.StateHash, tx.BindingHash, at)
	require.ErrorIs(t, err, oidcclient.ErrTransactionNotFound)
	require.NoError(t, b.Save(t.Context(), tx), "the same state hash under another prefix")

	got, err := a.Consume(t.Context(), tx.StateHash, tx.BindingHash, at)
	require.NoError(t, err)
	assert.Equal(t, tx.StateHash, got.StateHash)
}

// TestConsumedKeyKeepsItsTTL checks that a consumed transaction stays,
// flagged, until its key expires: its TTL is kept (KEEPTTL), and a second
// consumption finds nothing.
func TestConsumedKeyKeepsItsTTL(t *testing.T) {
	t.Parallel()

	store, mr := newStore(t)
	at := now()
	tx := sample("keepttl", at, 10*time.Minute)
	require.NoError(t, store.Save(t.Context(), tx))
	mr.FastForward(time.Minute)

	_, err := store.Consume(t.Context(), tx.StateHash, tx.BindingHash, at.Add(time.Minute))
	require.NoError(t, err)

	assert.Equal(t, 9*time.Minute, mr.TTL(key(tx.StateHash)))

	raw, err := mr.Get(key(tx.StateHash))
	require.NoError(t, err)
	assert.Contains(t, raw, `"consumed_by"`)

	_, err = store.Consume(t.Context(), tx.StateHash, tx.BindingHash, at.Add(time.Minute))
	require.ErrorIs(t, err, oidcclient.ErrTransactionNotFound)
	require.ErrorIs(t, store.Save(t.Context(), tx), oidcclient.ErrTransactionExists, "a consumed state hash is not reusable")
}

// TestConsumeDeletesExpired checks that an expired transaction is deleted
// when reached, whatever the binding.
func TestConsumeDeletesExpired(t *testing.T) {
	t.Parallel()

	store, mr := newStore(t)
	at := now()

	for _, binding := range []string{hash("binding-expired"), hash("another browser")} {
		tx := sample("expired", at.Add(-time.Minute), time.Minute)
		require.NoError(t, store.Save(t.Context(), tx))

		got, err := store.Consume(t.Context(), tx.StateHash, binding, at)
		require.ErrorIs(t, err, oidcclient.ErrTransactionNotFound)
		assert.Nil(t, got)
		assert.False(t, mr.Exists(key(tx.StateHash)))
	}
}

// resendHook runs the consume script twice, the way go-redis resends a
// command whose reply was lost.
type resendHook struct{ key string }

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
		}

		return next(ctx, cmd)
	}
}

// TestResentConsumeWins checks that the resend of a consumption still
// returns the transaction — the call consumed it — while any other call
// finds nothing.
func TestResentConsumeWins(t *testing.T) {
	t.Parallel()

	at := now()
	tx := sample("resent", at, time.Minute)

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	client.AddHook(&resendHook{key: key(tx.StateHash)})
	t.Cleanup(func() { _ = client.Close() })

	store, err := redisstore.New(client)
	require.NoError(t, err)
	require.NoError(t, store.Save(t.Context(), tx))

	got, err := store.Consume(t.Context(), tx.StateHash, tx.BindingHash, at)
	require.NoError(t, err)
	assert.Equal(t, *tx, *got, "the record re-encoded by cjson decodes unchanged")

	_, err = store.Consume(t.Context(), tx.StateHash, tx.BindingHash, at)
	require.ErrorIs(t, err, oidcclient.ErrTransactionNotFound)
}

// TestCorruptPayload checks that a payload the store cannot read fails the
// login without a verdict.
func TestCorruptPayload(t *testing.T) {
	t.Parallel()

	at := now()
	good := sample("corrupt", at, time.Minute)
	cases := map[string]string{
		"not JSON":             "{not-json",
		"no expiry":            `{"binding_hash":"` + good.BindingHash + `"}`,
		"string timestamps":    `{"binding_hash":"` + good.BindingHash + `","created_at":"1","expires_at":"99999999999"}`,
		"string expiry number": `{"binding_hash":"` + good.BindingHash + `","expires_at":"x"}`,
	}

	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			store, mr := newStore(t)
			require.NoError(t, mr.Set(key(good.StateHash), payload))

			got, err := store.Consume(t.Context(), good.StateHash, good.BindingHash, at)
			require.Error(t, err)
			assert.Nil(t, got)
			assert.NotErrorIs(t, err, oidcclient.ErrTransactionNotFound)
			assert.NotErrorIs(t, err, oidcclient.ErrBindingMismatch)
		})
	}
}

// TestBackendErrors closes the server so every command fails.
func TestBackendErrors(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = client.Close() })

	store, err := redisstore.New(client)
	require.NoError(t, err)

	mr.Close()

	at := now()
	tx := sample("down", at, time.Minute)

	err = store.Save(t.Context(), tx)
	require.Error(t, err)
	assert.NotErrorIs(t, err, oidcclient.ErrTransactionExists)

	_, err = store.Consume(t.Context(), tx.StateHash, tx.BindingHash, at)
	require.Error(t, err)
	assert.NotErrorIs(t, err, oidcclient.ErrTransactionNotFound)

	// Validated before any I/O.
	require.ErrorIs(t, store.Save(t.Context(), &oidcclient.Transaction{}), oidcclient.ErrInvalidTransaction)
}

// TestConsumeUnexpectedReply covers a script reply of another type.
func TestConsumeUnexpectedReply(t *testing.T) {
	t.Parallel()

	at := now()
	tx := sample("odd-reply", at, time.Minute)

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	var calls atomic.Int32

	client.AddHook(replyHook{calls: &calls})
	t.Cleanup(func() { _ = client.Close() })

	store, err := redisstore.New(client)
	require.NoError(t, err)

	_, err = store.Consume(t.Context(), tx.StateHash, tx.BindingHash, at)
	require.Error(t, err)
	assert.NotErrorIs(t, err, oidcclient.ErrTransactionNotFound)
	assert.Positive(t, calls.Load())
}

// replyHook answers every script with the integer 1.
type replyHook struct{ calls *atomic.Int32 }

func (replyHook) DialHook(next redis.DialHook) redis.DialHook { return next }

func (replyHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func (h replyHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if c, ok := cmd.(*redis.Cmd); ok && (cmd.Name() == "evalsha" || cmd.Name() == "eval") {
			h.calls.Add(1)
			c.SetVal(int64(1))

			return nil
		}

		return next(ctx, cmd)
	}
}
