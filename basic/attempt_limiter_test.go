// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package basic_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/basic"
	"github.com/hyperscale-stack/security/throttle"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// stepClock is a security.Clock the tests move by hand.
type stepClock struct {
	mu  sync.Mutex
	now time.Time
}

func newStepClock() *stepClock { return &stepClock{now: time.Unix(1_800_000_000, 0)} }

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

var noLimit = throttle.Limit{Failures: throttle.Unlimited}

// from returns a request context whose client address is ip.
func from(ip string) context.Context {
	return security.WithClientAddr(context.Background(), netip.MustParseAddr(ip))
}

// aliceLoader returns a generated UserLoader mock knowing alice, whose
// password is "right" for a recordingHasher matching "alice-hash", and
// expecting exactly lookups lookups.
func aliceLoader(t *testing.T, lookups int) *basic.MockUserLoader {
	t.Helper()

	l := basic.NewMockUserLoader(t)
	l.EXPECT().LoadByUsername(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, username string) (basic.PasswordUser, error) {
			if username != "alice" {
				return nil, nil
			}

			return mockUser(t, account{subject: "alice", hash: "alice-hash"}), nil
		}).
		Times(lookups)

	return l
}

func throttledClass(t *testing.T, err error) time.Duration {
	t.Helper()

	require.ErrorIs(t, err, security.ErrTooManyAttempts)
	assert.Equal(t, security.ErrorClassTooManyAttempts, security.ErrorClass(err))

	var tooMany *security.TooManyAttemptsError

	require.ErrorAs(t, err, &tooMany)

	return tooMany.RetryAfter
}

// NIST SP 800-63B-4 §3.2.2: failed attempts are limited. Once the
// allowance of (alice, source A) is spent, even the right password is
// refused before any lookup or verification; another source still signs
// in, and the allowance refills over time.
func TestAuthenticatorLimitsFailedAttempts(t *testing.T) {
	t.Parallel()

	clock := newStepClock()
	limiter := throttle.NewMemoryLimiter(throttle.Config{
		PerSubjectSource: throttle.Limit{Failures: 3, Window: 3 * time.Minute},
		PerSubject:       noLimit, PerSource: noLimit, Clock: clock,
	})
	hasher := &recordingHasher{match: "alice-hash"}
	a := basic.NewAuthenticator(aliceLoader(t, 5), hasher, basic.WithAttemptLimiter(limiter))
	baseline := len(hasher.calls())

	for range 3 {
		_, err := a.Authenticate(from("192.0.2.1"), basic.New("alice", "wrong"))
		require.ErrorIs(t, err, security.ErrInvalidCredentials)
	}

	out, err := a.Authenticate(from("192.0.2.1"), basic.New("alice", "right"))
	assert.Equal(t, time.Minute, throttledClass(t, err))
	assert.Equal(t, security.Anonymous(), out)
	assert.Len(t, hasher.calls(), baseline+3, "a throttled attempt verifies nothing")

	out, err = a.Authenticate(from("198.51.100.1"), basic.New("alice", "right"))
	require.NoError(t, err)
	assert.True(t, out.IsAuthenticated())

	clock.advance(time.Minute)

	_, err = a.Authenticate(from("192.0.2.1"), basic.New("alice", "right"))
	require.NoError(t, err)
}

// Unknown and known accounts are throttled alike: the limiter is no
// account-existence oracle.
func TestThrottlingDoesNotRevealAccounts(t *testing.T) {
	t.Parallel()

	delays := map[string]time.Duration{}

	for _, name := range []string{"alice", "nobody"} {
		limiter := throttle.NewMemoryLimiter(throttle.Config{
			PerSubjectSource: throttle.Limit{Failures: 2, Window: 2 * time.Minute},
			PerSubject:       noLimit, PerSource: noLimit, Clock: newStepClock(),
		})
		a := basic.NewAuthenticator(aliceLoader(t, 2), &recordingHasher{match: "alice-hash"}, basic.WithAttemptLimiter(limiter))

		for range 2 {
			_, err := a.Authenticate(from("192.0.2.1"), basic.New(name, "wrong"))
			require.ErrorIs(t, err, security.ErrInvalidCredentials)
		}

		_, err := a.Authenticate(from("192.0.2.1"), basic.New(name, "right"))
		delays[name] = throttledClass(t, err)
	}

	assert.Equal(t, delays["alice"], delays["nobody"])
}

// Every admitted attempt is settled exactly once, with its outcome, on a
// context that a canceled request does not cancel; the key is the realm
// "basic", the lower-cased user-id and the client address.
func TestAuthenticatorSettlesEveryAdmittedAttempt(t *testing.T) {
	t.Parallel()

	key := security.AttemptKey{Realm: "basic", Subject: "alice", Source: netip.MustParseAddr("192.0.2.1")}
	cases := []struct {
		name     string
		user     *account
		loadErr  error
		password string
		canceled bool
		want     security.AttemptOutcome
	}{
		{name: "success", user: &account{subject: "alice", hash: "alice-hash"}, password: "right", want: security.AttemptSucceeded},
		{name: "wrong password", user: &account{subject: "alice", hash: "alice-hash"}, password: "wrong", want: security.AttemptFailed},
		{name: "unknown user", password: "right", want: security.AttemptFailed},
		{name: "loader refusal", loadErr: errors.New("no such row"), password: "right", want: security.AttemptFailed},
		{name: "locked account", user: &account{subject: "alice", hash: "alice-hash", locked: true}, password: "right",
			want: security.AttemptFailed},
		{name: "user store down", loadErr: fmt.Errorf("db: %w", security.ErrUnavailable), password: "right",
			want: security.AttemptInconclusive},
		{name: "request ended before the verification", user: &account{subject: "alice", hash: "alice-hash"},
			password: "right", canceled: true, want: security.AttemptInconclusive},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			var user basic.PasswordUser
			if c.user != nil {
				user = mockUser(t, *c.user)
			}

			loader := basic.NewMockUserLoader(t)
			loader.EXPECT().LoadByUsername(mock.Anything, "Alice").Return(user, c.loadErr).Once()

			var recorded atomic.Bool

			limiter := basic.NewMockAttemptLimiter(t)
			limiter.EXPECT().Allow(mock.Anything, key).Return(nil).Once()
			limiter.EXPECT().Record(mock.Anything, key, c.want).
				Run(func(ctx context.Context, _ security.AttemptKey, _ security.AttemptOutcome) {
					assert.NoError(t, ctx.Err(), "Record outlives the request")
					recorded.Store(true)
				}).Once()

			ctx, cancel := context.WithCancel(from("192.0.2.1"))
			if c.canceled {
				cancel()
			}

			defer cancel()

			a := basic.NewAuthenticator(loader, &recordingHasher{match: "alice-hash"}, basic.WithAttemptLimiter(limiter))
			_, _ = a.Authenticate(ctx, basic.New("Alice", c.password))

			assert.True(t, recorded.Load())
		})
	}
}

// cancelingHasher cancels the request while it verifies — the client hung
// up after its guess was checked.
type cancelingHasher struct {
	recordingHasher

	cancel context.CancelFunc
}

func (h *cancelingHasher) Verify(ctx context.Context, hash, pw string) (bool, error) {
	h.cancel()

	return h.recordingHasher.Verify(ctx, hash, pw)
}

func TestAFailureIsRecordedWhenTheClientHangsUp(t *testing.T) {
	t.Parallel()

	key := security.AttemptKey{Realm: "basic", Subject: "alice", Source: netip.MustParseAddr("192.0.2.1")}

	limiter := basic.NewMockAttemptLimiter(t)
	limiter.EXPECT().Allow(mock.Anything, key).Return(nil).Once()
	limiter.EXPECT().Record(mock.Anything, key, security.AttemptFailed).
		Run(func(ctx context.Context, _ security.AttemptKey, _ security.AttemptOutcome) {
			assert.NoError(t, ctx.Err())
		}).Once()

	ctx, cancel := context.WithCancel(from("192.0.2.1"))
	defer cancel()

	hasher := &cancelingHasher{recordingHasher: recordingHasher{match: "alice-hash"}, cancel: cancel}
	a := basic.NewAuthenticator(aliceLoader(t, 1), hasher, basic.WithAttemptLimiter(limiter))

	_, err := a.Authenticate(ctx, basic.New("alice", "wrong"))
	require.ErrorIs(t, err, security.ErrInvalidCredentials)
}

// Malformed credentials are refused before any lookup: they reach no
// limiter either (the generated mock fails on any call).
func TestMalformedCredentialsNeverReachTheLimiter(t *testing.T) {
	t.Parallel()

	a := basic.NewAuthenticator(basic.NewMockUserLoader(t), newHasher(t),
		basic.WithAttemptLimiter(basic.NewMockAttemptLimiter(t)))

	for _, in := range []basic.Authentication{basic.New("al\x00ice", "pw"), basic.New("", "pw"), basic.New("alice", "p​w")} {
		_, err := a.Authenticate(from("192.0.2.1"), in)
		require.ErrorIs(t, err, basic.ErrBadFormat)
	}
}

// A refusal of the limiter refuses the attempt before any lookup, and the
// attempt is not settled. An error that is neither a throttle nor an outage
// is answered as an outage: fail closed.
func TestLimiterRefusals(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		err   error
		class string
	}{
		{"throttled", &security.TooManyAttemptsError{RetryAfter: time.Minute}, security.ErrorClassTooManyAttempts},
		{"limiter store down", fmt.Errorf("redis: %w", security.ErrUnavailable), security.ErrorClassUnavailable},
		{"request canceled", context.Canceled, security.ErrorClassUnavailable},
		{"no sentinel", errors.New("boom"), security.ErrorClassUnavailable},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			limiter := basic.NewMockAttemptLimiter(t)
			limiter.EXPECT().Allow(mock.Anything, mock.Anything).Return(c.err).Once()

			a := basic.NewAuthenticator(basic.NewMockUserLoader(t), newHasher(t), basic.WithAttemptLimiter(limiter))

			out, err := a.Authenticate(from("192.0.2.1"), basic.New("alice", "right"))
			require.ErrorIs(t, err, c.err)
			assert.Equal(t, c.class, security.ErrorClass(err))
			assert.Equal(t, security.Anonymous(), out)
		})
	}
}

// The user-ids the account store resolves to one account share one
// allowance: lower-cased by default, normalized by WithAttemptSubject.
func TestAttemptSubjectNormalization(t *testing.T) {
	t.Parallel()

	newLimiter := func() *throttle.MemoryLimiter {
		return throttle.NewMemoryLimiter(throttle.Config{
			PerSubjectSource: throttle.Limit{Failures: 2, Window: 2 * time.Minute},
			PerSubject:       noLimit, PerSource: noLimit, Clock: newStepClock(),
		})
	}

	t.Run("lower-cased by default", func(t *testing.T) {
		t.Parallel()

		a := basic.NewAuthenticator(unknownUsers(t), &recordingHasher{}, basic.WithAttemptLimiter(newLimiter()))

		for _, name := range []string{"Alice", "ALICE"} {
			_, err := a.Authenticate(from("192.0.2.1"), basic.New(name, "wrong"))
			require.ErrorIs(t, err, security.ErrInvalidCredentials)
		}

		_, err := a.Authenticate(from("192.0.2.1"), basic.New("alice", "wrong"))
		throttledClass(t, err)
	})

	t.Run("custom", func(t *testing.T) {
		t.Parallel()

		fold := func(s string) string { return strings.ToLower(strings.ReplaceAll(s, "á", "a")) }
		a := basic.NewAuthenticator(unknownUsers(t), &recordingHasher{},
			basic.WithAttemptLimiter(newLimiter()), basic.WithAttemptSubject(fold))

		for _, name := range []string{"ádmin", "Admin"} {
			_, err := a.Authenticate(from("192.0.2.1"), basic.New(name, "wrong"))
			require.ErrorIs(t, err, security.ErrInvalidCredentials)
		}

		_, err := a.Authenticate(from("192.0.2.1"), basic.New("ADMIN", "wrong"))
		throttledClass(t, err)
	})
}

// Without a client address in the context the source is unknown: only the
// per-subject allowance applies.
func TestUnknownSourceMeetsThePerSubjectAllowance(t *testing.T) {
	t.Parallel()

	limiter := throttle.NewMemoryLimiter(throttle.Config{
		PerSubjectSource: throttle.Limit{Failures: 1, Window: time.Minute},
		PerSource:        throttle.Limit{Failures: 1, Window: time.Minute},
		PerSubject:       throttle.Limit{Failures: 3, Window: 3 * time.Minute},
		Clock:            newStepClock(),
	})
	a := basic.NewAuthenticator(unknownUsers(t), &recordingHasher{}, basic.WithAttemptLimiter(limiter))

	for range 3 {
		_, err := a.Authenticate(context.Background(), basic.New("alice", "wrong"))
		require.ErrorIs(t, err, security.ErrInvalidCredentials)
	}

	_, err := a.Authenticate(context.Background(), basic.New("alice", "wrong"))
	throttledClass(t, err)
}

// openHasher accepts every password once released, and counts the
// verifications running.
type openHasher struct {
	release chan struct{}
	running atomic.Int32
}

func (h *openHasher) Hash(context.Context, string) (string, error) { return "dummy", nil }

func (h *openHasher) Verify(context.Context, string, string) (bool, error) {
	h.running.Add(1)
	<-h.release

	return true, nil
}

func (h *openHasher) NeedsRehash(string) bool { return false }

// Legitimate concurrency pays for the reservations too: K concurrent
// correct attempts get the allowance admitted until they are settled.
func TestConcurrentCorrectAttemptsHoldReservations(t *testing.T) {
	t.Parallel()

	limiter := throttle.NewMemoryLimiter(throttle.Config{
		PerSubjectSource: throttle.Limit{Failures: 3, Window: 3 * time.Minute},
		PerSubject:       noLimit, PerSource: noLimit, Clock: newStepClock(),
	})
	h := &openHasher{release: make(chan struct{})}
	a := basic.NewAuthenticator(aliceLoader(t, 4), h,
		basic.WithAttemptLimiter(limiter), basic.WithMaxConcurrentVerifications(10))

	var (
		wg        sync.WaitGroup
		succeeded atomic.Int32
		throttled atomic.Int32
	)

	for range 5 {
		wg.Go(func() {
			_, err := a.Authenticate(from("192.0.2.1"), basic.New("alice", "right"))

			switch {
			case err == nil:
				succeeded.Add(1)
			case errors.Is(err, security.ErrTooManyAttempts):
				throttled.Add(1)
			}
		})
	}

	require.Eventually(t, func() bool { return throttled.Load() == 2 && h.running.Load() == 3 }, 5*time.Second, time.Millisecond)

	close(h.release)
	wg.Wait()

	assert.EqualValues(t, 3, succeeded.Load())

	_, err := a.Authenticate(from("192.0.2.1"), basic.New("alice", "right"))
	require.NoError(t, err, "the successes settled their reservations")
}

func TestAttemptOptionsRefuseNil(t *testing.T) {
	t.Parallel()

	assert.Panics(t, func() { basic.WithAttemptLimiter(nil) })
	assert.Panics(t, func() { basic.WithAttemptLimiter((*throttle.MemoryLimiter)(nil)) })
	assert.Panics(t, func() { basic.WithAttemptSubject(nil) })
}
