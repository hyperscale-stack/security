// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package throttle_test

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/throttle"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeClock is a security.Clock the tests move by hand.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = c.now.Add(d)
}

var off = throttle.Limit{Failures: throttle.Unlimited}

// only returns a Config whose budgets are all disabled but the ones set by
// set.
func only(clock security.Clock, set func(*throttle.Config)) throttle.Config {
	cfg := throttle.Config{PerSubjectSource: off, PerSubject: off, PerSource: off, Clock: clock}
	set(&cfg)

	return cfg
}

func key(subject, source string) security.AttemptKey {
	k := security.AttemptKey{Realm: "basic", Subject: subject}
	if source != "" {
		k.Source = netip.MustParseAddr(source)
	}

	return k
}

// fail runs one admitted attempt that fails, and fails the test when it is
// refused.
func fail(t *testing.T, l *throttle.MemoryLimiter, k security.AttemptKey) {
	t.Helper()

	require.NoError(t, l.Allow(context.Background(), k), "attempt %v refused", k)
	l.Record(context.Background(), k, security.AttemptFailed)
}

// refused asserts that l refuses k and returns the advertised delay.
func refused(t *testing.T, l *throttle.MemoryLimiter, k security.AttemptKey) time.Duration {
	t.Helper()

	err := l.Allow(context.Background(), k)
	require.ErrorIs(t, err, security.ErrTooManyAttempts, "attempt %v admitted", k)
	assert.NotErrorIs(t, err, security.ErrUnavailable)

	var tooMany *security.TooManyAttemptsError

	require.ErrorAs(t, err, &tooMany)
	require.Positive(t, tooMany.RetryAfter)

	return tooMany.RetryAfter
}

func TestMemoryLimiterImplementsTheContract(t *testing.T) {
	t.Parallel()

	var _ security.AttemptLimiter = throttle.NewMemoryLimiter(throttle.Config{})

	// The wall clock, nil or given, drives the default configuration.
	for _, clock := range []security.Clock{nil, security.SystemClock{}} {
		l := throttle.NewMemoryLimiter(throttle.Config{Clock: clock})

		for range 10 {
			fail(t, l, key("alice", "192.0.2.1"))
		}

		refused(t, l, key("alice", "192.0.2.1"))
	}
}

// NIST SP 800-63B-4 §3.2.2: failed attempts are limited. The allowance is
// a burst of Failures, refilled one attempt every Window/Failures.
func TestBurstThenOneAttemptPerInterval(t *testing.T) {
	t.Parallel()

	clock := newClock()
	l := throttle.NewMemoryLimiter(only(clock, func(c *throttle.Config) {
		c.PerSubjectSource = throttle.Limit{Failures: 3, Window: 3 * time.Minute}
	}))
	k := key("alice", "192.0.2.1")

	for range 3 {
		fail(t, l, k)
	}

	assert.Equal(t, time.Minute, refused(t, l, k))

	clock.Advance(time.Minute - time.Nanosecond)
	assert.Equal(t, time.Nanosecond, refused(t, l, k))

	clock.Advance(time.Nanosecond)
	fail(t, l, k)
	assert.Equal(t, time.Minute, refused(t, l, k), "one attempt regained, one spent")

	clock.Advance(3 * time.Minute)

	for range 3 {
		fail(t, l, k)
	}

	refused(t, l, k)
}

func TestDefaults(t *testing.T) {
	t.Parallel()

	t.Run("per subject and source: 10 per 15 minutes", func(t *testing.T) {
		t.Parallel()

		l := throttle.NewMemoryLimiter(throttle.Config{Clock: newClock()})
		k := key("alice", "192.0.2.1")

		for range 10 {
			fail(t, l, k)
		}

		assert.Equal(t, 90*time.Second, refused(t, l, k))
	})

	t.Run("per source: 100 per 15 minutes, every subject", func(t *testing.T) {
		t.Parallel()

		l := throttle.NewMemoryLimiter(throttle.Config{Clock: newClock()})

		for i := range 100 {
			fail(t, l, key(fmt.Sprintf("user-%d", i), "192.0.2.1"))
		}

		assert.Equal(t, 9*time.Second, refused(t, l, key("user-100", "192.0.2.1")))
		fail(t, l, key("user-100", "192.0.2.2"))
	})

	t.Run("per subject: 100 per hour, every source", func(t *testing.T) {
		t.Parallel()

		l := throttle.NewMemoryLimiter(throttle.Config{Clock: newClock()})

		for i := range 100 {
			fail(t, l, key("alice", fmt.Sprintf("192.0.2.%d", i+1)))
		}

		assert.Equal(t, 36*time.Second, refused(t, l, key("alice", "198.51.100.1")))
		fail(t, l, key("bob", "198.51.100.1"))
	})

	t.Run("IPv6 per /56", func(t *testing.T) {
		t.Parallel()

		l := throttle.NewMemoryLimiter(throttle.Config{Clock: newClock()})

		for i := range 10 {
			fail(t, l, key("alice", fmt.Sprintf("2001:db8:0:%x::1", i)))
		}

		refused(t, l, key("alice", "2001:db8:0:ff::2")) // same /56
		fail(t, l, key("alice", "2001:db8:0:100::1"))   // next /56
	})
}

// RFC 6177 §1/§3: an end site holds far more than one /64 — a /56 is the
// common assignment —, so per-source budgets count IPv6 clients per /56 by
// default; IPv4 clients per address.
func TestSourcesAreAggregated(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		prefixLen int
		a, b      string
		shared    bool
	}{
		{"same /56", 0, "2001:db8:aa:bb00::1", "2001:db8:aa:bbff:ffff::9", true},
		{"other /56", 0, "2001:db8:aa:bb00::1", "2001:db8:aa:bc00::1", false},
		{"/55 split", 0, "2001:db8:aa:ba00::1", "2001:db8:aa:bb00::1", false},
		{"same /64 at 64", 64, "2001:db8::1", "2001:db8::ffff", true},
		{"other /64 at 64", 64, "2001:db8:0:0::1", "2001:db8:0:1::1", false},
		{"same /48 at 48", 48, "2001:db8:1:ffff::1", "2001:db8:1:0::1", true},
		{"IPv4 per address", 0, "192.0.2.1", "192.0.2.2", false},
		{"IPv4-mapped is IPv4", 0, "::ffff:192.0.2.1", "192.0.2.1", true},
		{"zone ignored", 0, "fe80::1%eth0", "fe80::1%eth1", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			l := throttle.NewMemoryLimiter(only(newClock(), func(cfg *throttle.Config) {
				cfg.PerSubjectSource = throttle.Limit{Failures: 1, Window: time.Minute}
				cfg.IPv6PrefixLen = c.prefixLen
			}))

			fail(t, l, key("alice", c.a))

			err := l.Allow(context.Background(), key("alice", c.b))
			if c.shared {
				require.ErrorIs(t, err, security.ErrTooManyAttempts)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// The core anti-lock-out property: a refused attempt charges no budget, so
// a source that keeps trying burns nothing more — neither its own
// allowance nor the subject's.
func TestARefusalChargesNoBudget(t *testing.T) {
	t.Parallel()

	t.Run("per-source refusal leaves the subject budget", func(t *testing.T) {
		t.Parallel()

		l := throttle.NewMemoryLimiter(only(newClock(), func(c *throttle.Config) {
			c.PerSubjectSource = throttle.Limit{Failures: 2, Window: 2 * time.Minute}
			c.PerSubject = throttle.Limit{Failures: 3, Window: 3 * time.Minute}
		}))

		fail(t, l, key("alice", "192.0.2.1"))
		fail(t, l, key("alice", "192.0.2.1"))

		before := refused(t, l, key("alice", "192.0.2.1"))

		for range 1000 {
			assert.Equal(t, before, refused(t, l, key("alice", "192.0.2.1")))
		}

		fail(t, l, key("alice", "198.51.100.1")) // the subject's third
		refused(t, l, key("alice", "203.0.113.1"))
	})

	t.Run("subject refusal leaves the per-source budgets", func(t *testing.T) {
		t.Parallel()

		clock := newClock()
		l := throttle.NewMemoryLimiter(only(clock, func(c *throttle.Config) {
			c.PerSubject = throttle.Limit{Failures: 1, Window: time.Minute}
			c.PerSubjectSource = throttle.Limit{Failures: 5, Window: 5 * time.Minute}
			c.PerSource = throttle.Limit{Failures: 5, Window: 5 * time.Minute}
		}))

		fail(t, l, key("alice", "192.0.2.1"))

		for range 100 {
			refused(t, l, key("alice", "192.0.2.1"))
		}

		clock.Advance(time.Minute)
		fail(t, l, key("alice", "192.0.2.1")) // the per-source budgets were not burnt
	})
}

func TestRetryAfterIsTheLongestWait(t *testing.T) {
	t.Parallel()

	l := throttle.NewMemoryLimiter(only(newClock(), func(c *throttle.Config) {
		c.PerSubjectSource = throttle.Limit{Failures: 1, Window: time.Minute}
		c.PerSubject = throttle.Limit{Failures: 1, Window: time.Hour}
	}))

	fail(t, l, key("alice", "192.0.2.1"))

	assert.Equal(t, time.Hour, refused(t, l, key("alice", "192.0.2.1")))
}

func TestRetryAfterStaysPositiveWhenTheClockGoesBack(t *testing.T) {
	t.Parallel()

	clock := newClock()
	l := throttle.NewMemoryLimiter(only(clock, func(c *throttle.Config) {
		c.PerSubjectSource = throttle.Limit{Failures: 1, Window: time.Minute}
	}))

	fail(t, l, key("alice", "192.0.2.1"))
	clock.Advance(-time.Hour)

	assert.Equal(t, time.Hour+time.Minute, refused(t, l, key("alice", "192.0.2.1")))
}

// N guesses sent at once cannot all pass the check before the first
// failure is recorded: Allow reserves the attempt.
func TestConcurrentAttemptsNeverExceedTheAllowance(t *testing.T) {
	t.Parallel()

	l := throttle.NewMemoryLimiter(only(newClock(), func(c *throttle.Config) {
		c.PerSubjectSource = throttle.Limit{Failures: 10, Window: 10 * time.Minute}
	}))

	var (
		admitted atomic.Int32
		wg       sync.WaitGroup
		start    = make(chan struct{})
	)

	for range 200 {
		wg.Go(func() {
			<-start

			if l.Allow(context.Background(), key("alice", "192.0.2.1")) == nil {
				admitted.Add(1)
			}
		})
	}

	close(start)
	wg.Wait()

	assert.EqualValues(t, 10, admitted.Load(), "reserved attempts count until they are settled")
}

func TestSourcesRacingForTheLastSubjectAttempt(t *testing.T) {
	t.Parallel()

	l := throttle.NewMemoryLimiter(only(newClock(), func(c *throttle.Config) {
		c.PerSubject = throttle.Limit{Failures: 5, Window: 5 * time.Minute}
		c.PerSubjectSource = throttle.Limit{Failures: 5, Window: 5 * time.Minute}
	}))

	for i := range 4 {
		fail(t, l, key("alice", fmt.Sprintf("192.0.2.%d", i+1)))
	}

	var (
		admitted atomic.Int32
		wg       sync.WaitGroup
		start    = make(chan struct{})
	)

	for i := range 100 {
		wg.Go(func() {
			<-start

			if l.Allow(context.Background(), key("alice", fmt.Sprintf("198.51.100.%d", i+1))) == nil {
				admitted.Add(1)
			}
		})
	}

	close(start)
	wg.Wait()

	assert.EqualValues(t, 1, admitted.Load())
}

// Legitimate concurrency pays for the reservation too: K parallel correct
// attempts get N admitted until a success settles one.
func TestReservationsHoldUntilSettled(t *testing.T) {
	t.Parallel()

	l := throttle.NewMemoryLimiter(only(newClock(), func(c *throttle.Config) {
		c.PerSubjectSource = throttle.Limit{Failures: 3, Window: 3 * time.Minute}
	}))
	k := key("alice", "192.0.2.1")

	for range 3 {
		require.NoError(t, l.Allow(context.Background(), k))
	}

	refused(t, l, k)

	l.Record(context.Background(), k, security.AttemptSucceeded)
	require.NoError(t, l.Allow(context.Background(), k))
}

// A success clears the failures of its own (subject, source) entry and
// refunds its own charge elsewhere; it does not reset the subject's
// cross-source budget, which other sources keep burning.
func TestSuccessResetsOnlyItsOwnSource(t *testing.T) {
	t.Parallel()

	l := throttle.NewMemoryLimiter(only(newClock(), func(c *throttle.Config) {
		c.PerSubjectSource = throttle.Limit{Failures: 3, Window: 3 * time.Minute}
		c.PerSubject = throttle.Limit{Failures: 5, Window: 5 * time.Minute}
	}))
	a, b := key("alice", "192.0.2.1"), key("alice", "198.51.100.1")

	fail(t, l, a)
	fail(t, l, a)
	fail(t, l, b)
	fail(t, l, b)

	require.NoError(t, l.Allow(context.Background(), a))
	l.Record(context.Background(), a, security.AttemptSucceeded)

	// The subject budget still holds the four failures: one attempt left.
	fail(t, l, a)
	refused(t, l, a)
	refused(t, l, b)

	// A's own entry was cleared: once the subject budget refills, A has
	// its full burst again, B only what it had left.
	l2 := throttle.NewMemoryLimiter(only(newClock(), func(c *throttle.Config) {
		c.PerSubjectSource = throttle.Limit{Failures: 3, Window: 3 * time.Minute}
	}))

	fail(t, l2, a)
	fail(t, l2, a)
	fail(t, l2, b)
	fail(t, l2, b)

	require.NoError(t, l2.Allow(context.Background(), a))
	l2.Record(context.Background(), a, security.AttemptSucceeded)

	for range 3 {
		fail(t, l2, a)
	}

	refused(t, l2, a)
	fail(t, l2, b)
	refused(t, l2, b)
}

func TestOutcomes(t *testing.T) {
	t.Parallel()

	limit := func(c *throttle.Config) {
		c.PerSubjectSource = throttle.Limit{Failures: 2, Window: 2 * time.Minute}
		c.PerSubject = throttle.Limit{Failures: 2, Window: 2 * time.Minute}
		c.PerSource = throttle.Limit{Failures: 2, Window: 2 * time.Minute}
	}
	k := key("alice", "192.0.2.1")

	t.Run("inconclusive refunds every budget", func(t *testing.T) {
		t.Parallel()

		l := throttle.NewMemoryLimiter(only(newClock(), limit))

		for range 100 {
			require.NoError(t, l.Allow(context.Background(), k))
			l.Record(context.Background(), k, security.AttemptInconclusive)
		}

		fail(t, l, k)
		fail(t, l, k)
		refused(t, l, k)
	})

	t.Run("failed keeps the charge", func(t *testing.T) {
		t.Parallel()

		l := throttle.NewMemoryLimiter(only(newClock(), limit))

		fail(t, l, k)
		fail(t, l, k)
		refused(t, l, k)
	})

	t.Run("an unknown outcome counts as failed", func(t *testing.T) {
		t.Parallel()

		l := throttle.NewMemoryLimiter(only(newClock(), limit))

		for range 2 {
			require.NoError(t, l.Allow(context.Background(), k))
			l.Record(context.Background(), k, security.AttemptOutcome(42))
		}

		refused(t, l, k)
	})
}

// Record settles a reservation; it never creates credit.
func TestRecordNeverCreatesCredit(t *testing.T) {
	t.Parallel()

	limit := func(c *throttle.Config) {
		c.PerSubjectSource = throttle.Limit{Failures: 3, Window: 3 * time.Minute}
		c.PerSubject = throttle.Limit{Failures: 3, Window: 3 * time.Minute}
		c.PerSource = throttle.Limit{Failures: 3, Window: 3 * time.Minute}
	}
	k := key("alice", "192.0.2.1")

	t.Run("two refunds for one reservation", func(t *testing.T) {
		t.Parallel()

		l := throttle.NewMemoryLimiter(only(newClock(), limit))

		fail(t, l, k)
		fail(t, l, k)
		require.NoError(t, l.Allow(context.Background(), k))
		l.Record(context.Background(), k, security.AttemptInconclusive)
		l.Record(context.Background(), k, security.AttemptInconclusive)
		l.Record(context.Background(), k, security.AttemptInconclusive)

		fail(t, l, k)
		refused(t, l, k)
	})

	t.Run("a refund after the charge expired", func(t *testing.T) {
		t.Parallel()

		clock := newClock()
		l := throttle.NewMemoryLimiter(only(clock, limit))

		require.NoError(t, l.Allow(context.Background(), k))
		clock.Advance(time.Hour)
		l.Record(context.Background(), k, security.AttemptInconclusive)

		for range 3 {
			fail(t, l, k)
		}

		refused(t, l, k)
	})

	t.Run("a success without a reservation", func(t *testing.T) {
		t.Parallel()

		l := throttle.NewMemoryLimiter(only(newClock(), limit))

		for range 3 {
			fail(t, l, k)
		}

		l.Record(context.Background(), k, security.AttemptSucceeded)
		l.Record(context.Background(), k, security.AttemptInconclusive)
		refused(t, l, k)
	})

	t.Run("a record for a key never seen", func(t *testing.T) {
		t.Parallel()

		l := throttle.NewMemoryLimiter(only(newClock(), limit))

		for _, o := range []security.AttemptOutcome{security.AttemptFailed, security.AttemptSucceeded, security.AttemptInconclusive} {
			l.Record(context.Background(), key("nobody", "203.0.113.9"), o)
		}

		for range 3 {
			fail(t, l, k)
		}

		refused(t, l, k)
	})
}

// A zero source is unknown: only the subject budget applies — an unknown
// source never shares one small per-source allowance with every other.
func TestUnknownSourceSkipsTheSourceBudgets(t *testing.T) {
	t.Parallel()

	l := throttle.NewMemoryLimiter(only(newClock(), func(c *throttle.Config) {
		c.PerSubjectSource = throttle.Limit{Failures: 1, Window: time.Minute}
		c.PerSource = throttle.Limit{Failures: 1, Window: time.Minute}
		c.PerSubject = throttle.Limit{Failures: 3, Window: 3 * time.Minute}
	}))

	for range 3 {
		fail(t, l, key("alice", ""))
	}

	refused(t, l, key("alice", ""))
	fail(t, l, key("bob", ""))
}

func TestBudgetsAreIndependentPerKeyPart(t *testing.T) {
	t.Parallel()

	t.Run("per source spans subjects", func(t *testing.T) {
		t.Parallel()

		l := throttle.NewMemoryLimiter(only(newClock(), func(c *throttle.Config) {
			c.PerSource = throttle.Limit{Failures: 3, Window: 3 * time.Minute}
		}))

		for i := range 3 {
			fail(t, l, key(fmt.Sprintf("user-%d", i), "192.0.2.1"))
		}

		refused(t, l, key("user-3", "192.0.2.1"))
		fail(t, l, key("user-3", "192.0.2.2"))
	})

	t.Run("per subject spans sources", func(t *testing.T) {
		t.Parallel()

		l := throttle.NewMemoryLimiter(only(newClock(), func(c *throttle.Config) {
			c.PerSubject = throttle.Limit{Failures: 3, Window: 3 * time.Minute}
		}))

		for i := range 3 {
			fail(t, l, key("alice", fmt.Sprintf("192.0.2.%d", i+1)))
		}

		refused(t, l, key("alice", "198.51.100.1"))
		fail(t, l, key("bob", "198.51.100.1"))
	})

	t.Run("realms are apart", func(t *testing.T) {
		t.Parallel()

		l := throttle.NewMemoryLimiter(only(newClock(), func(c *throttle.Config) {
			c.PerSubjectSource = throttle.Limit{Failures: 1, Window: time.Minute}
			c.PerSubject = throttle.Limit{Failures: 1, Window: time.Minute}
			c.PerSource = throttle.Limit{Failures: 1, Window: time.Minute}
		}))

		k := key("alice", "192.0.2.1")
		fail(t, l, k)
		refused(t, l, k)

		k.Realm = "oauth2/password"
		fail(t, l, k)
	})

	t.Run("subject and realm are not concatenated", func(t *testing.T) {
		t.Parallel()

		l := throttle.NewMemoryLimiter(only(newClock(), func(c *throttle.Config) {
			c.PerSubject = throttle.Limit{Failures: 1, Window: time.Minute}
		}))

		fail(t, l, security.AttemptKey{Realm: "ab", Subject: "c"})
		fail(t, l, security.AttemptKey{Realm: "a", Subject: "bc"})

		// Fields are length-prefixed, not merely separated.
		nul := strings.Repeat("\x00", 8)
		fail(t, l, security.AttemptKey{Realm: "a" + nul + "b", Subject: "c"})
		fail(t, l, security.AttemptKey{Realm: "a", Subject: "b" + nul + "c"})
	})

	t.Run("an empty subject is a key of its own", func(t *testing.T) {
		t.Parallel()

		l := throttle.NewMemoryLimiter(only(newClock(), func(c *throttle.Config) {
			c.PerSubjectSource = throttle.Limit{Failures: 1, Window: time.Minute}
		}))

		fail(t, l, key("", "192.0.2.1"))
		refused(t, l, key("", "192.0.2.1"))
		fail(t, l, key("alice", "192.0.2.1"))
	})
}

func TestNewMemoryLimiterRefusesAConfigurationThatFailsOpen(t *testing.T) {
	t.Parallel()

	cases := map[string]throttle.Config{
		"no failures":          {PerSubject: throttle.Limit{Window: time.Minute}},
		"no window":            {PerSubject: throttle.Limit{Failures: 3}},
		"negative failures":    {PerSource: throttle.Limit{Failures: -2, Window: time.Minute}},
		"negative window":      {PerSubjectSource: throttle.Limit{Failures: 3, Window: -time.Minute}},
		"interval rounds to 0": {PerSubjectSource: throttle.Limit{Failures: 10, Window: 5 * time.Nanosecond}},
		"unlimited and window": {PerSubject: throttle.Limit{Failures: throttle.Unlimited, Window: time.Minute}},
		"max keys too small":   {MaxKeys: 2},
		"negative max keys":    {MaxKeys: -1},
		"IPv6 prefix /47":      {IPv6PrefixLen: 47},
		"IPv6 prefix /65":      {IPv6PrefixLen: 65},
		"negative IPv6 prefix": {IPv6PrefixLen: -1},
		"typed-nil clock":      {Clock: (*fakeClock)(nil)},
	}

	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Panics(t, func() { throttle.NewMemoryLimiter(cfg) })
		})
	}
}

func TestEveryBudgetCanBeDisabled(t *testing.T) {
	t.Parallel()

	l := throttle.NewMemoryLimiter(only(newClock(), func(*throttle.Config) {}))

	for range 1000 {
		fail(t, l, key("alice", "192.0.2.1"))
	}
}
