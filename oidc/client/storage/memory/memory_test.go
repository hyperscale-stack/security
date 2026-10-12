// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package memory_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	"github.com/hyperscale-stack/security/oidc/client/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func hash(s string) string {
	sum := sha256.Sum256([]byte(s))

	return hex.EncodeToString(sum[:])
}

func transaction(seed string, created time.Time, ttl time.Duration) *oidcclient.Transaction {
	return &oidcclient.Transaction{
		StateHash:    hash("state-" + seed),
		BindingHash:  hash("binding-" + seed),
		ConnectionID: "acme",
		Issuer:       "https://idp.example.com",
		ClientID:     "client-1",
		RedirectURI:  "https://rp.example.com/callback",
		ResponseMode: oidcclient.ResponseModeQuery,
		MaxAge:       oidcclient.NoMaxAge,
		CreatedAt:    created,
		ExpiresAt:    created.Add(ttl),
		Integrity:    hash("integrity-" + seed),
	}
}

// TestSweepExpired checks that abandoned logins do not accumulate: expired
// transactions are swept while new ones are saved, without any Consume.
func TestSweepExpired(t *testing.T) {
	t.Parallel()

	s := memory.New()
	start := time.Unix(1_800_000_000, 0).UTC()

	for i := range 200 {
		require.NoError(t, s.Save(context.Background(), transaction("old-"+strconv.Itoa(i), start, time.Minute)))
	}

	later := start.Add(time.Hour)

	for i := range 200 {
		require.NoError(t, s.Save(context.Background(), transaction("new-"+strconv.Itoa(i), later, time.Minute)))
	}

	assert.LessOrEqual(t, s.Len(), 264, "the expired transactions are swept by later saves")
	assert.GreaterOrEqual(t, s.Len(), 200, "live transactions are kept")
}

// TestSaveKeepsACopy checks that the store does not alias the caller's
// transaction.
func TestSaveKeepsACopy(t *testing.T) {
	t.Parallel()

	s := memory.New()
	now := time.Unix(1_800_000_000, 0).UTC()
	tx := transaction("copy", now, time.Minute)

	require.NoError(t, s.Save(context.Background(), tx))

	tx.ConnectionID = "tampered"

	got, err := s.Consume(context.Background(), hash("state-copy"), hash("binding-copy"), now)
	require.NoError(t, err)
	assert.Equal(t, "acme", got.ConnectionID)
}

// TestCapacity checks WithCapacity: the store keeps at most n live
// transactions, refuses the next with ErrFull without storing it nor
// evicting a pending login, and takes one again once a slot is free.
func TestCapacity(t *testing.T) {
	t.Parallel()

	s := memory.New(memory.WithCapacity(3))
	now := time.Unix(1_800_000_000, 0).UTC()

	for i := range 3 {
		require.NoError(t, s.Save(context.Background(), transaction("live-"+strconv.Itoa(i), now, 10*time.Minute)))
	}

	err := s.Save(context.Background(), transaction("refused", now, 10*time.Minute))
	require.ErrorIs(t, err, memory.ErrFull)
	assert.Equal(t, 3, s.Len())

	_, err = s.Consume(context.Background(), hash("state-refused"), hash("binding-refused"), now)
	require.ErrorIs(t, err, oidcclient.ErrTransactionNotFound, "a refused transaction is not stored")

	_, err = s.Consume(context.Background(), hash("state-live-0"), hash("binding-live-0"), now)
	require.NoError(t, err, "the pending logins are kept")

	require.NoError(t, s.Save(context.Background(), transaction("after", now, 10*time.Minute)), "a consumed slot is free again")
	assert.Equal(t, 3, s.Len())
}

// TestCapacityDropsExpiredFirst checks that a full store drops its expired
// transactions before refusing — without waiting for the periodic sweep.
func TestCapacityDropsExpiredFirst(t *testing.T) {
	t.Parallel()

	s := memory.New(memory.WithCapacity(2))
	start := time.Unix(1_800_000_000, 0).UTC()

	require.NoError(t, s.Save(context.Background(), transaction("old-1", start, time.Minute)))
	require.NoError(t, s.Save(context.Background(), transaction("old-2", start, time.Minute)))
	require.ErrorIs(t, s.Save(context.Background(), transaction("early", start.Add(30*time.Second), time.Minute)), memory.ErrFull)

	require.NoError(t, s.Save(context.Background(), transaction("new", start.Add(time.Minute), time.Minute)),
		"at their expiry the old transactions make room")
	assert.Equal(t, 1, s.Len())
}

// TestCapacityDuplicateIsExists checks that a full store still reports a
// duplicate state hash as ErrTransactionExists.
func TestCapacityDuplicateIsExists(t *testing.T) {
	t.Parallel()

	s := memory.New(memory.WithCapacity(1))
	now := time.Unix(1_800_000_000, 0).UTC()

	require.NoError(t, s.Save(context.Background(), transaction("one", now, time.Minute)))
	require.ErrorIs(t, s.Save(context.Background(), transaction("one", now, time.Minute)), oidcclient.ErrTransactionExists)
}

// TestCapacityConcurrentSaves checks the bound under concurrency: exactly
// n of many concurrent saves succeed.
func TestCapacityConcurrentSaves(t *testing.T) {
	t.Parallel()

	const capacity, savers = 10, 100

	s := memory.New(memory.WithCapacity(capacity))
	now := time.Unix(1_800_000_000, 0).UTC()

	var (
		wg         sync.WaitGroup
		saved, full atomic.Int64
	)

	for i := range savers {
		wg.Go(func() {
			switch err := s.Save(context.Background(), transaction("c-"+strconv.Itoa(i), now, time.Minute)); {
			case err == nil:
				saved.Add(1)
			case errors.Is(err, memory.ErrFull):
				full.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		})
	}

	wg.Wait()
	assert.Equal(t, int64(capacity), saved.Load())
	assert.Equal(t, int64(savers-capacity), full.Load())
	assert.Equal(t, capacity, s.Len())
}

// TestWithCapacityRefusesLessThanOne checks that a capacity below one is a
// programming error: a bound computed as zero never silently disables
// itself.
func TestWithCapacityRefusesLessThanOne(t *testing.T) {
	t.Parallel()

	for _, n := range []int{0, -1} {
		assert.Panics(t, func() { memory.WithCapacity(n) }, "WithCapacity(%d)", n)
	}
}

// TestNoCapacityByDefault checks that New without options keeps every
// transaction, as before WithCapacity existed.
func TestNoCapacityByDefault(t *testing.T) {
	t.Parallel()

	s := memory.New()
	now := time.Unix(1_800_000_000, 0).UTC()

	for i := range 2_000 {
		require.NoError(t, s.Save(context.Background(), transaction("d-"+strconv.Itoa(i), now, time.Minute)))
	}

	assert.Equal(t, 2_000, s.Len())
}
