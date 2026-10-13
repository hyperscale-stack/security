// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package basic_test

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/basic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// gateHasher blocks every Verify until release is closed and tracks how
// many run at once.
type gateHasher struct {
	release  chan struct{}
	running  atomic.Int32
	max      atomic.Int32
	verifies atomic.Int32
}

func newGateHasher() *gateHasher { return &gateHasher{release: make(chan struct{})} }

func (h *gateHasher) Hash(context.Context, string) (string, error) { return "dummy", nil }

func (h *gateHasher) Verify(ctx context.Context, _, _ string) (bool, error) {
	h.verifies.Add(1)

	n := h.running.Add(1)
	defer h.running.Add(-1)

	for {
		m := h.max.Load()
		if n <= m || h.max.CompareAndSwap(m, n) {
			break
		}
	}

	select {
	case <-h.release:
		return false, nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

func (h *gateHasher) NeedsRehash(string) bool { return false }

// runAttempts starts n concurrent attempts and returns a function waiting
// for them — failing the test, instead of hanging it, when they do not end.
func runAttempts(t *testing.T, a *basic.Authenticator, n int) func() {
	t.Helper()

	var wg sync.WaitGroup

	for i := range n {
		wg.Add(1)

		go func() {
			defer wg.Done()

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			_, _ = a.Authenticate(ctx, basic.New(fmt.Sprintf("user-%d", i), "pw"))
		}()
	}

	return func() {
		t.Helper()

		done := make(chan struct{})

		go func() {
			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("attempts did not end: a verification slot leaked")
		}
	}
}

// assertConcurrencyCap starts more attempts than limit and checks that
// exactly limit verifications run at once, then that every attempt ends.
func assertConcurrencyCap(t *testing.T, a *basic.Authenticator, h *gateHasher, limit, attempts int) {
	t.Helper()

	wait := runAttempts(t, a, attempts)

	require.Eventually(t, func() bool { return h.running.Load() >= int32(limit) }, 5*time.Second, time.Millisecond) //nolint:gosec // small test values
	time.Sleep(20 * time.Millisecond)                                                                               // give extra attempts a chance to overshoot
	assert.Equal(t, int32(limit), h.max.Load(), "verifications running at once")                                    //nolint:gosec // small test values

	close(h.release)
	wait()

	assert.Equal(t, int32(attempts), h.verifies.Load(), "every attempt was verified once") //nolint:gosec // small test values
}

// Audit CORE-12 (probe TestZZAuditArgon2idConcurrentMemory: 16 concurrent
// default argon2id verifications allocated 304 MiB) and review finding 1:
// once every attempt costs a hash (CORE-03), an unbounded number of
// concurrent attempts — with any username — exhausts memory. By default an
// Authenticator runs at most runtime.GOMAXPROCS(0) verifications at once:
// CPU-bound hashing gains nothing from more.
func TestAuthenticatorCapsConcurrentVerificationsByDefault(t *testing.T) {
	t.Parallel()

	h := newGateHasher()
	limit := runtime.GOMAXPROCS(0)

	assertConcurrencyCap(t, basic.NewAuthenticator(unknownUsers(t), h), h, limit, limit+5)
}

func TestWithMaxConcurrentVerifications(t *testing.T) {
	t.Parallel()

	h := newGateHasher()
	a := basic.NewAuthenticator(unknownUsers(t), h, basic.WithMaxConcurrentVerifications(3))

	assertConcurrencyCap(t, a, h, 3, 12)
}

// UnlimitedVerifications removes the cap (for a hasher that is not CPU-bound,
// such as one calling a remote HSM).
func TestUnlimitedVerifications(t *testing.T) {
	t.Parallel()

	h := newGateHasher()
	limit := runtime.GOMAXPROCS(0) + 8
	a := basic.NewAuthenticator(unknownUsers(t), h, basic.WithMaxConcurrentVerifications(basic.UnlimitedVerifications))

	assertConcurrencyCap(t, a, h, limit, limit)
}

func TestWithMaxConcurrentVerificationsPanics(t *testing.T) {
	t.Parallel()

	for _, n := range []int{0, -2, -100} {
		assert.Panics(t, func() { basic.WithMaxConcurrentVerifications(n) }, "n=%d", n)
	}
}

// An attempt waiting for a slot gives up when its context ends: the
// credentials were not checked, so the answer is ErrUnavailable (503), never
// ErrInvalidCredentials — and the same for an unknown user, or an overload
// would tell which accounts exist.
func TestAuthenticatorVerificationQueueHonorsTheContext(t *testing.T) {
	t.Parallel()

	h := newGateHasher()
	alice := mockUser(t, account{subject: "alice", hash: "hash"})
	users := mockLoader(t, func(username string) (basic.PasswordUser, error) {
		if username == "alice" {
			return alice, nil
		}

		return nil, security.ErrInvalidCredentials
	})
	a := basic.NewAuthenticator(users, h, basic.WithMaxConcurrentVerifications(1))

	wait := runAttempts(t, a, 1) // holds the only slot
	require.Eventually(t, func() bool { return h.running.Load() == 1 }, 5*time.Second, time.Millisecond)

	for _, username := range []string{"alice", "nobody"} {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)

		type result struct {
			out security.Authentication
			err error
		}

		done := make(chan result, 1)

		go func() {
			out, err := a.Authenticate(ctx, basic.New(username, "pw"))
			done <- result{out, err}
		}()

		var r result

		select {
		case r = <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: the attempt kept waiting after its context ended", username)
		}

		cancel()

		out, err := r.out, r.err

		require.ErrorIs(t, err, security.ErrUnavailable, username)
		assert.NotErrorIs(t, err, security.ErrInvalidCredentials, username)
		assert.Equal(t, security.ErrorClassUnavailable, security.ErrorClass(err), username)
		assert.False(t, out.IsAuthenticated())
	}

	assert.Equal(t, int32(1), h.verifies.Load(), "the queued attempts never reached Verify")

	close(h.release)
	wait()
}

// ctxHasher returns a context error, as a hasher does when the request's
// context ended between the slot and the hashing.
type ctxHasher struct{ recordingHasher }

func (h *ctxHasher) Verify(context.Context, string, string) (bool, error) {
	return false, fmt.Errorf("password: context canceled: %w", context.DeadlineExceeded)
}

func TestAuthenticatorMapsAContextEndedVerificationToUnavailable(t *testing.T) {
	t.Parallel()

	a := basic.NewAuthenticator(unknownUsers(t), &ctxHasher{})

	_, err := a.Authenticate(context.Background(), basic.New("nobody", "pw"))

	require.ErrorIs(t, err, security.ErrUnavailable)
	assert.NotErrorIs(t, err, security.ErrInvalidCredentials)
}

// rehashingLoader is a UserLoader that also stores new password hashes
// (PasswordRehasher), made of the two generated mocks. Without an
// UpdatePasswordHash expectation, any call fails the test.
type rehashingLoader struct {
	*basic.MockUserLoader
	*basic.MockPasswordRehasher
}

// newRehashingLoader returns a rehashingLoader whose lookups of "alice"
// return user.
func newRehashingLoader(t *testing.T, user basic.PasswordUser) rehashingLoader {
	t.Helper()

	l := rehashingLoader{basic.NewMockUserLoader(t), basic.NewMockPasswordRehasher(t)}
	l.MockUserLoader.EXPECT().LoadByUsername(mock.Anything, "alice").Return(user, nil).Once()

	return l
}

// Review finding 2: the dummy hash costs what a hash at the hasher's current
// parameters costs; stored hashes made with other parameters keep a timing
// difference until they are re-hashed. A loader implementing
// PasswordRehasher gets the stored hash upgraded after a successful
// authentication whose hash NeedsRehash.
func TestAuthenticatorRehashesOutdatedHashes(t *testing.T) {
	t.Parallel()

	alice := account{subject: "alice", hash: "old"}

	t.Run("outdated hash is re-hashed after a success", func(t *testing.T) {
		t.Parallel()

		user := mockUser(t, alice)
		l := newRehashingLoader(t, user)
		l.MockPasswordRehasher.EXPECT().UpdatePasswordHash(mock.Anything, user, "dummy-2").Return(nil).Once() // the new hash comes from the hasher
		a := basic.NewAuthenticator(l, &recordingHasher{match: "old", rehash: true})

		out, err := a.Authenticate(context.Background(), basic.New("alice", "right"))

		require.NoError(t, err)
		assert.True(t, out.IsAuthenticated())
	})

	t.Run("current hash is left alone", func(t *testing.T) {
		t.Parallel()

		l := newRehashingLoader(t, mockUser(t, alice)) // no UpdatePasswordHash expected
		a := basic.NewAuthenticator(l, &recordingHasher{match: "old"})

		_, err := a.Authenticate(context.Background(), basic.New("alice", "right"))

		require.NoError(t, err)
	})

	for name, mod := range map[string]func(*account){
		"wrong password": func(a *account) { a.hash = "other" },
		"locked account": func(a *account) { a.locked = true },
	} {
		t.Run("no rehash on a failure: "+name, func(t *testing.T) {
			t.Parallel()

			u := alice
			mod(&u)
			l := newRehashingLoader(t, mockUser(t, u)) // no UpdatePasswordHash expected
			a := basic.NewAuthenticator(l, &recordingHasher{match: "old", rehash: true})

			_, err := a.Authenticate(context.Background(), basic.New("alice", "right"))

			require.ErrorIs(t, err, security.ErrInvalidCredentials)
		})
	}

	t.Run("a failed update does not fail the authentication", func(t *testing.T) {
		t.Parallel()

		user := mockUser(t, alice)
		l := newRehashingLoader(t, user)
		l.MockPasswordRehasher.EXPECT().UpdatePasswordHash(mock.Anything, user, mock.Anything).Return(errors.New("store read-only")).Once()
		a := basic.NewAuthenticator(l, &recordingHasher{match: "old", rehash: true})

		out, err := a.Authenticate(context.Background(), basic.New("alice", "right"))

		require.NoError(t, err)
		assert.True(t, out.IsAuthenticated())
	})

	t.Run("a loader without PasswordRehasher is never asked", func(t *testing.T) {
		t.Parallel()

		l := basic.NewMockUserLoader(t)
		l.EXPECT().LoadByUsername(mock.Anything, "alice").Return(mockUser(t, alice), nil).Once()
		a := basic.NewAuthenticator(l, &recordingHasher{match: "old", rehash: true})

		out, err := a.Authenticate(context.Background(), basic.New("alice", "right"))

		require.NoError(t, err)
		assert.True(t, out.IsAuthenticated())
	})
}

// failingRehashHasher verifies, asks for a rehash, but cannot hash again.
type failingRehashHasher struct{ recordingHasher }

func (h *failingRehashHasher) Hash(ctx context.Context, pw string) (string, error) {
	if h.hashes > 0 {
		return "", errors.New("hsm offline")
	}

	return h.recordingHasher.Hash(ctx, pw)
}

func TestAuthenticatorIgnoresAFailedRehash(t *testing.T) {
	t.Parallel()

	l := newRehashingLoader(t, mockUser(t, account{subject: "alice", hash: "old"})) // no UpdatePasswordHash expected
	a := basic.NewAuthenticator(l, &failingRehashHasher{recordingHasher{match: "old", rehash: true}})

	out, err := a.Authenticate(context.Background(), basic.New("alice", "right"))

	require.NoError(t, err)
	assert.True(t, out.IsAuthenticated())
}

// A context that ended during the verification gets no slot for the
// rehash: the stored hash stays as it is and the authentication succeeds.
func TestAuthenticatorSkipsTheRehashWhenTheContextEnded(t *testing.T) {
	t.Parallel()

	l := newRehashingLoader(t, mockUser(t, account{subject: "alice", hash: "old"})) // no UpdatePasswordHash expected
	h := &recordingHasher{match: "old", rehash: true, delay: 40 * time.Millisecond} // Verify ignores ctx
	a := basic.NewAuthenticator(l, h)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	out, err := a.Authenticate(ctx, basic.New("alice", "right"))

	require.NoError(t, err)
	assert.True(t, out.IsAuthenticated())
}

// downHasher cannot verify: its Verify wraps security.ErrUnavailable, as a
// hasher calling a remote HSM or pepper service does while it is down.
type downHasher struct{ recordingHasher }

func (*downHasher) Verify(context.Context, string, string) (bool, error) {
	return false, fmt.Errorf("hsm: %w", security.ErrUnavailable)
}

// Review finding 2: a hasher that cannot verify is answered 503 for every
// account. Answered 401 for unknown accounts and 503 for known ones, the
// status code would tell which accounts exist during the outage.
func TestAuthenticatorAnswersAnUnavailableHasherAlikeForEveryAccount(t *testing.T) {
	t.Parallel()

	for _, c := range attempts("real-hash") {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			a := basic.NewAuthenticator(c.loader(t), &downHasher{})

			out, err := a.Authenticate(context.Background(), basic.New("alice", c.password))

			require.ErrorIs(t, err, security.ErrUnavailable)
			assert.Equal(t, security.ErrorClassUnavailable, security.ErrorClass(err))
			assert.False(t, out.IsAuthenticated())
		})
	}
}

// A canceled request never starts a verification.
func TestAuthenticatorDoesNotVerifyForACanceledRequest(t *testing.T) {
	t.Parallel()

	h := &recordingHasher{}
	a := basic.NewAuthenticator(unknownUsers(t), h)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := a.Authenticate(ctx, basic.New("nobody", "right"))

	require.ErrorIs(t, err, security.ErrUnavailable)
	assert.Empty(t, h.calls())
}

// Every attempt gives its slot back: with one slot, sequential attempts never
// wait.
func TestAuthenticatorReleasesItsSlots(t *testing.T) {
	t.Parallel()

	a := basic.NewAuthenticator(unknownUsers(t), &recordingHasher{}, basic.WithMaxConcurrentVerifications(1))

	for i := range 5 {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)

		_, err := a.Authenticate(ctx, basic.New("nobody", "right"))

		cancel()

		require.ErrorIs(t, err, security.ErrInvalidCredentials, "attempt %d", i)
		require.NotErrorIs(t, err, security.ErrUnavailable, "attempt %d waited for a slot", i)
	}
}
