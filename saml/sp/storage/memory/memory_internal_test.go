// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package memory

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	samlsp "github.com/hyperscale-stack/security/saml/sp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var base = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)

// testClock is a settable clock.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *testClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = t
}

func hexKey(prefix string, n int) string { return fmt.Sprintf("%s%062x", prefix, n) }

func record(n int, expiresAt time.Time) *samlsp.TransactionRecord {
	return &samlsp.TransactionRecord{
		ID:          hexKey("aa", n),
		BindingHash: hexKey("bb", n),
		Integrity:   hexKey("cc", n),
		Payload:     "payload",
		ExpiresAt:   expiresAt,
	}
}

// fill makes n writes that never expire within the tests (replay marks a
// day ahead), to reach a sweep.
func fill(t *testing.T, s *Store, from, n int) {
	t.Helper()

	for i := range n {
		require.NoError(t, s.MarkAssertionUsed(context.Background(), hexKey("ff", from+i), base.Add(24*time.Hour)))
	}
}

func sizes(s *Store) (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.txs), len(s.used)
}

func TestSweep_DeletesRecordsAtTheirExpiry(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	clk := &testClock{now: base}
	s := New(WithClock(clk.Now))
	exp := base.Add(time.Minute)

	require.NoError(t, s.SaveTransaction(ctx, record(1, exp)))
	require.NoError(t, s.MarkAssertionUsed(ctx, hexKey("dd", 1), exp))

	// One second before the expiry, a sweep keeps both.
	clk.set(exp.Add(-time.Second))
	fill(t, s, 0, sweepEvery)

	txs, used := sizes(s)
	assert.Equal(t, 1, txs, "pending transaction kept before its expiry")
	assert.Equal(t, 1+sweepEvery, used, "replay mark kept before its expiry")

	// At the expiry (Storage contract: expired at ExpiresAt), the next
	// sweep deletes both.
	clk.set(exp)
	fill(t, s, sweepEvery, sweepEvery)

	txs, used = sizes(s)
	assert.Equal(t, 0, txs)
	assert.Equal(t, 2*sweepEvery, used, "only the expired mark is gone")

	_, err := s.LookupTransaction(ctx, record(1, exp).ID)
	require.ErrorIs(t, err, samlsp.ErrTransactionNotFound)
	require.NoError(t, s.MarkAssertionUsed(ctx, hexKey("dd", 1), exp.Add(time.Hour)), "a purged mark is gone")
}

func TestSweep_KeepsConsumedRecordsAndMarksUntilTheirExpiry(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	clk := &testClock{now: base}
	s := New(WithClock(clk.Now))
	rec := record(1, base.Add(10*time.Minute))
	mark := hexKey("dd", 1)

	require.NoError(t, s.SaveTransaction(ctx, rec))
	require.NoError(t, s.ConsumeTransaction(ctx, rec.ID, rec.BindingHash))
	require.NoError(t, s.MarkAssertionUsed(ctx, mark, base.Add(11*time.Minute)))

	clk.set(base.Add(10*time.Minute - time.Second))
	fill(t, s, 0, 3*sweepEvery)

	_, err := s.LookupTransaction(ctx, rec.ID)
	require.ErrorIs(t, err, samlsp.ErrTransactionConsumed, "never consumable again before its expiry")
	require.ErrorIs(t, s.ConsumeTransaction(ctx, rec.ID, rec.BindingHash), samlsp.ErrTransactionConsumed)
	require.ErrorIs(t, s.MarkAssertionUsed(ctx, mark, base.Add(11*time.Minute)), samlsp.ErrAssertionReplayed)
}

// The earliest expiry tracked spans both maps: a replay mark expiring
// before every transaction is swept, and the transaction survives.
func TestSweep_NextExpirySpansBothMaps(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	clk := &testClock{now: base}
	s := New(WithClock(clk.Now))
	rec := record(1, base.Add(10*time.Minute))

	require.NoError(t, s.SaveTransaction(ctx, rec))
	require.NoError(t, s.MarkAssertionUsed(ctx, hexKey("dd", 1), base.Add(time.Minute)))

	clk.set(base.Add(time.Minute))
	fill(t, s, 0, sweepEvery)

	txs, used := sizes(s)
	assert.Equal(t, 1, txs, "the transaction survives")
	assert.Equal(t, sweepEvery, used, "the expired mark is swept")
	assert.Equal(t, 1, s.sweeps)
	assert.True(t, s.nextExpiry.Equal(rec.ExpiresAt), "next expiry is the transaction's: %s", s.nextExpiry)

	_, err := s.LookupTransaction(ctx, rec.ID)
	require.NoError(t, err)
}

// Sweeps are amortized: one every sweepEvery writes, and a walk only once
// the earliest expiry has passed.
func TestSweep_IsAmortized(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	clk := &testClock{now: base}
	s := New(WithClock(clk.Now))

	require.NoError(t, s.SaveTransaction(ctx, record(1, base.Add(time.Minute))))

	// Before the earliest expiry: no walk, however many writes.
	fill(t, s, 0, 2*sweepEvery)
	assert.Equal(t, 0, s.sweeps)

	// Past it: no walk before the next multiple of sweepEvery writes.
	clk.set(base.Add(time.Hour))

	writes := s.writes
	fill(t, s, 2*sweepEvery, sweepEvery-1-writes%sweepEvery)
	assert.Equal(t, 0, s.sweeps)

	fill(t, s, 3*sweepEvery, 1)
	assert.Equal(t, 1, s.sweeps)

	txs, _ := sizes(s)
	assert.Equal(t, 0, txs)

	// Lookups and consumptions are not writes: they never sweep.
	for range 2 * sweepEvery {
		_, _ = s.LookupTransaction(ctx, record(2, base).ID)
	}

	assert.Equal(t, 1, s.sweeps)
}

// Without WithClock the store sweeps on the wall clock.
func TestNew_SweepsOnTheWallClockByDefault(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := New()
	past := time.Now().Add(-time.Minute).Truncate(time.Second)

	require.NoError(t, s.SaveTransaction(ctx, record(1, past)))

	for i := range sweepEvery {
		require.NoError(t, s.MarkAssertionUsed(ctx, hexKey("ff", i), time.Now().Add(time.Hour).Truncate(time.Second)))
	}

	txs, _ := sizes(s)
	assert.Equal(t, 0, txs)
}

func TestWithClock_RefusesNil(t *testing.T) {
	t.Parallel()

	assert.PanicsWithValue(t, "memory: WithClock: nil clock", func() { WithClock(nil) })
}
