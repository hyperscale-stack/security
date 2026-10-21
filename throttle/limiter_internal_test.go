// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package throttle

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/hyperscale-stack/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stepClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *stepClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *stepClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = c.now.Add(d)
}

var disabled = Limit{Failures: Unlimited}

func attempt(subject, source string) security.AttemptKey {
	return security.AttemptKey{Realm: "basic", Subject: subject, Source: netip.MustParseAddr(source)}
}

func mustFail(t *testing.T, l *MemoryLimiter, k security.AttemptKey) {
	t.Helper()

	require.NoError(t, l.Allow(context.Background(), k))
	l.Record(context.Background(), k, security.AttemptFailed)
}

// consistent checks that the map and the heap hold the same entries, each
// at its heap index.
func consistent(t *testing.T, l *MemoryLimiter) {
	t.Helper()

	l.mu.Lock()
	defer l.mu.Unlock()

	require.Len(t, l.heap, len(l.entries))

	for i, e := range l.heap {
		assert.Equal(t, i, e.index)
		assert.Same(t, e, l.entries[e.key])
	}
}

// A flood of fresh keys cannot grow the table past MaxKeys, nor flush the
// entry of a throttled key: the least throttled entries go first.
func TestMemoryStaysBoundedAndKeepsTheThrottledKey(t *testing.T) {
	t.Parallel()

	clock := &stepClock{now: time.Unix(1_800_000_000, 0)}
	l := NewMemoryLimiter(Config{
		PerSubjectSource: Limit{Failures: 3, Window: 3 * time.Minute},
		PerSubject:       disabled, PerSource: disabled,
		MaxKeys: 10, Clock: clock,
	})
	victim := attempt("alice", "192.0.2.1")

	for range 3 {
		mustFail(t, l, victim)
	}

	for i := range 1000 {
		mustFail(t, l, attempt(fmt.Sprintf("user-%d", i), "198.51.100.1"))
		require.LessOrEqual(t, len(l.entries), 10)
	}

	consistent(t, l)
	require.ErrorIs(t, l.Allow(context.Background(), victim), security.ErrTooManyAttempts)
}

// The incoming entry is never the eviction victim: a new key arriving in a
// table full of more throttled keys is still tracked, and refused after
// exactly its allowance.
func TestANewKeyIsTrackedInAFullTable(t *testing.T) {
	t.Parallel()

	clock := &stepClock{now: time.Unix(1_800_000_000, 0)}
	l := NewMemoryLimiter(Config{
		PerSubjectSource: Limit{Failures: 2, Window: 2 * time.Minute},
		PerSubject:       disabled, PerSource: disabled,
		MaxKeys: 3, Clock: clock,
	})

	for i := range 3 {
		mustFail(t, l, attempt(fmt.Sprintf("user-%d", i), "198.51.100.1"))
		mustFail(t, l, attempt(fmt.Sprintf("user-%d", i), "198.51.100.1"))
	}

	k := attempt("alice", "192.0.2.1")

	mustFail(t, l, k)
	mustFail(t, l, k)
	require.ErrorIs(t, l.Allow(context.Background(), k), security.ErrTooManyAttempts)
	consistent(t, l)
}

// Making room for an attempt never evicts another entry of that same
// attempt, even when it is the least throttled one.
func TestEvictionSparesTheAttemptsOwnEntries(t *testing.T) {
	t.Parallel()

	clock := &stepClock{now: time.Unix(1_800_000_000, 0)}
	l := NewMemoryLimiter(Config{
		PerSubjectSource: Limit{Failures: 2, Window: 2 * time.Minute},
		PerSubject:       Limit{Failures: 10, Window: 10 * time.Minute},
		PerSource:        disabled,
		MaxKeys:          3, Clock: clock,
	})

	x := attempt("x", "198.51.100.1")
	mustFail(t, l, x)
	mustFail(t, l, x)

	y := attempt("y", "192.0.2.1")
	mustFail(t, l, y)
	mustFail(t, l, y)
	require.ErrorIs(t, l.Allow(context.Background(), y), security.ErrTooManyAttempts)
	consistent(t, l)
}

// An attempt whose source entry already exists — and is the least
// throttled one — must not lose it to make room for its other entries: that
// would forgive the source's earlier failures.
func TestEvictionSparesAnExistingEntryOfTheAttempt(t *testing.T) {
	t.Parallel()

	clock := &stepClock{now: time.Unix(1_800_000_000, 0)}
	l := NewMemoryLimiter(Config{
		PerSubjectSource: Limit{Failures: 5, Window: 5 * time.Minute},
		PerSource:        Limit{Failures: 5, Window: 5 * time.Minute},
		PerSubject:       disabled,
		MaxKeys:          3, Clock: clock,
	})

	// Source B: two failures, then a success that clears its (z, B) entry
	// and leaves the per-source entry of B, two charges.
	z := attempt("z", "192.0.2.1")
	mustFail(t, l, z)
	mustFail(t, l, z)
	require.NoError(t, l.Allow(context.Background(), z))
	l.Record(context.Background(), z, security.AttemptSucceeded)

	// Source A fills the table with more throttled entries.
	for range 3 {
		mustFail(t, l, attempt("x", "198.51.100.1"))
	}

	// B's next attempts find its per-source entry the least throttled.
	mustFail(t, l, attempt("y", "192.0.2.1"))
	mustFail(t, l, attempt("w1", "192.0.2.1"))
	mustFail(t, l, attempt("w2", "192.0.2.1"))
	require.ErrorIs(t, l.Allow(context.Background(), attempt("w3", "192.0.2.1")), security.ErrTooManyAttempts,
		"source B made its five failures")
	consistent(t, l)
}

// Entries whose every charge has expired carry nothing: they are purged.
func TestRecoveredEntriesArePurged(t *testing.T) {
	t.Parallel()

	clock := &stepClock{now: time.Unix(1_800_000_000, 0)}
	l := NewMemoryLimiter(Config{Clock: clock})

	for i := range 50 {
		mustFail(t, l, attempt(fmt.Sprintf("user-%d", i), fmt.Sprintf("192.0.2.%d", i+1)))
	}

	require.Len(t, l.entries, 150)

	clock.advance(time.Hour)
	mustFail(t, l, attempt("alice", "203.0.113.1"))

	assert.Len(t, l.entries, 3, "only the last attempt's three entries remain")
	consistent(t, l)
}

func TestDisabledBudgetsTrackNothing(t *testing.T) {
	t.Parallel()

	l := NewMemoryLimiter(Config{PerSubjectSource: disabled, PerSubject: disabled, PerSource: disabled})

	for i := range 100 {
		mustFail(t, l, attempt(fmt.Sprintf("user-%d", i), "192.0.2.1"))
	}

	assert.Empty(t, l.entries)
}

// The settle path keeps the heap consistent under concurrency.
func TestConcurrentUseKeepsTheTableConsistent(t *testing.T) {
	t.Parallel()

	clock := &stepClock{now: time.Unix(1_800_000_000, 0)}
	l := NewMemoryLimiter(Config{MaxKeys: 64, Clock: clock})

	var wg sync.WaitGroup

	for g := range 16 {
		wg.Go(func() {
			for i := range 200 {
				k := attempt(fmt.Sprintf("user-%d", i%20), fmt.Sprintf("192.0.2.%d", g+1))
				if l.Allow(context.Background(), k) == nil {
					l.Record(context.Background(), k, security.AttemptOutcome(i%3))
				}

				if i%50 == 0 {
					clock.advance(time.Second)
				}
			}
		})
	}

	wg.Wait()
	consistent(t, l)
	assert.LessOrEqual(t, len(l.entries), 64)
}
