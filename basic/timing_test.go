// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package basic_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/basic"
	"github.com/hyperscale-stack/security/password"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The password.Hasher doubles of these tests (recordingHasher, gateHasher and
// their variants, recordingWrapper) are hand-written: mockery generates
// in-package mocks, so password's MockHasher exists only in the password
// package's own test binary, not in this one.

// recordingHasher is a password.Hasher fake: Hash returns a fresh
// "dummy-N" value; Verify waits `delay`, records the hash it was given and
// accepts the password "right" against the hash `match` — or every
// password against every hash when `always` is set.
type recordingHasher struct {
	mu       sync.Mutex
	hashes   int
	verified []string
	match    string
	always   bool
	delay    time.Duration
	rehash   bool
	hashErr  error
}

func (h *recordingHasher) Hash(context.Context, string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.hashErr != nil {
		return "", h.hashErr
	}

	h.hashes++

	return "dummy-" + string(rune('0'+h.hashes)), nil
}

func (h *recordingHasher) Verify(_ context.Context, hash, pw string) (bool, error) {
	time.Sleep(h.delay)

	h.mu.Lock()
	defer h.mu.Unlock()

	h.verified = append(h.verified, hash)

	return h.always || (h.match != "" && hash == h.match && pw == "right"), nil
}

func (h *recordingHasher) NeedsRehash(string) bool { return h.rehash }

func (h *recordingHasher) calls() []string {
	h.mu.Lock()
	defer h.mu.Unlock()

	return slices.Clone(h.verified)
}

// account is the user record behind a generated PasswordUser mock.
type account struct {
	subject, hash                                 string
	disabled, locked, expired, credentialsExpired bool
}

// mockUser returns a generated PasswordUser mock answering with a: the
// Authenticator may read each field any number of times.
func mockUser(t *testing.T, a account) *basic.MockPasswordUser {
	t.Helper()

	u := basic.NewMockPasswordUser(t)
	u.EXPECT().Subject().Return(a.subject).Maybe()
	u.EXPECT().GetPasswordHash().Return(a.hash).Maybe()
	u.EXPECT().IsEnabled().Return(!a.disabled).Maybe()
	u.EXPECT().IsLocked().Return(a.locked).Maybe()
	u.EXPECT().IsExpired().Return(a.expired).Maybe()
	u.EXPECT().IsCredentialsExpired().Return(a.credentialsExpired).Maybe()

	return u
}

// mockLoader returns a generated UserLoader mock answering every lookup with
// load, from any goroutine, any number of times.
func mockLoader(t *testing.T, load func(username string) (basic.PasswordUser, error)) *basic.MockUserLoader {
	t.Helper()

	l := basic.NewMockUserLoader(t)
	l.EXPECT().LoadByUsername(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, username string) (basic.PasswordUser, error) { return load(username) }).
		Maybe()

	return l
}

// unknownUsers returns a generated UserLoader mock that knows nobody.
func unknownUsers(t *testing.T) *basic.MockUserLoader {
	t.Helper()

	l := basic.NewMockUserLoader(t)
	l.EXPECT().LoadByUsername(mock.Anything, mock.Anything).Return(nil, nil).Maybe()

	return l
}

// attempt is one outcome an attacker could tell apart by timing.
type attempt struct {
	name     string
	user     *account // nil: the loader returns no user
	loadErr  error
	password string
	dummy    bool // verified against the dummy hash
}

// loader returns a generated UserLoader mock expecting the attempt's single
// lookup of "alice".
func (c attempt) loader(t *testing.T) *basic.MockUserLoader {
	t.Helper()

	var user basic.PasswordUser
	if c.user != nil {
		user = mockUser(t, *c.user)
	}

	l := basic.NewMockUserLoader(t)
	l.EXPECT().LoadByUsername(mock.Anything, "alice").Return(user, c.loadErr).Once()

	return l
}

// attempts lists every outcome an attacker could tell apart by timing.
func attempts(real string) []attempt {
	user := func(mod func(*account)) *account {
		a := &account{subject: "alice", hash: real}
		mod(a)

		return a
	}

	return []attempt{
		{name: "unknown user (nil, nil)", password: "right", dummy: true},
		{name: "unknown user (ErrInvalidCredentials)", loadErr: security.ErrInvalidCredentials, password: "right", dummy: true},
		{name: "loader failure", loadErr: errors.New("store down"), password: "right", dummy: true},
		{name: "account without a password hash", user: user(func(a *account) { a.hash = "" }), password: "right", dummy: true},
		{name: "disabled", user: user(func(a *account) { a.disabled = true }), password: "right"},
		{name: "locked", user: user(func(a *account) { a.locked = true }), password: "right"},
		{name: "expired", user: user(func(a *account) { a.expired = true }), password: "right"},
		{name: "credentials expired", user: user(func(a *account) { a.credentialsExpired = true }), password: "right"},
		{name: "wrong password", user: user(func(*account) {}), password: "wrong"},
	}
}

// Audit CORE-03 (probe TestZZAuditBasicTimingOracle): unknown, disabled,
// locked and expired accounts returned before the password check — 267 µs
// against 62.5 ms for a known user with bcrypt cost 10 — so the response
// time told which accounts exist. Every attempt now runs exactly one
// password verification: against the user's hash, or against a dummy hash
// the configured hasher made at construction; the account state is read
// after it.
func TestAuthenticatorVerifiesExactlyOncePerAttempt(t *testing.T) {
	t.Parallel()

	for _, c := range attempts("real-hash") {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			h := &recordingHasher{match: "real-hash"}
			a := basic.NewAuthenticator(c.loader(t), h)

			out, err := a.Authenticate(context.Background(), basic.New("alice", c.password))

			require.ErrorIs(t, err, security.ErrInvalidCredentials)
			assert.False(t, out.IsAuthenticated())
			assert.Equal(t, security.Anonymous(), out, "a failure never hands the credentials back")

			want := "real-hash"
			if c.dummy {
				want = "dummy-1" // the hash the hasher produced at construction
			}

			assert.Equal(t, []string{want}, h.calls())
		})
	}
}

// Review finding 7: a hasher that accepts every password (buggy, custom,
// or the dummy matching by chance) never authenticates a refused account:
// the refusals are checked after the verification, not instead of it.
func TestAuthenticatorRefusalsHoldWhateverTheHasherAnswers(t *testing.T) {
	t.Parallel()

	for _, c := range attempts("real-hash") {
		if c.password == "wrong" {
			continue // the only refusal the hasher decides
		}

		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			h := &recordingHasher{always: true}
			a := basic.NewAuthenticator(c.loader(t), h)

			out, err := a.Authenticate(context.Background(), basic.New("alice", c.password))

			require.ErrorIs(t, err, security.ErrInvalidCredentials)
			assert.False(t, out.IsAuthenticated())
			assert.Len(t, h.calls(), 1)
		})
	}
}

// The account state is read after the password: a locked account answers
// the same with the right and the wrong password.
func TestAuthenticatorChecksTheAccountStateAfterThePassword(t *testing.T) {
	t.Parallel()

	h := &recordingHasher{match: "real-hash"}
	locked := mockUser(t, account{subject: "alice", hash: "real-hash", locked: true})
	l := basic.NewMockUserLoader(t)
	l.EXPECT().LoadByUsername(mock.Anything, "alice").Return(locked, nil).Twice()
	a := basic.NewAuthenticator(l, h)

	_, rightErr := a.Authenticate(context.Background(), basic.New("alice", "right"))
	_, wrongErr := a.Authenticate(context.Background(), basic.New("alice", "wrong"))

	require.ErrorIs(t, rightErr, security.ErrInvalidCredentials)
	require.ErrorIs(t, wrongErr, security.ErrInvalidCredentials)
	assert.Equal(t, []string{"real-hash", "real-hash"}, h.calls())
}

// Robust timing check: a Verify that takes at least `delay` makes every
// refused attempt take at least `delay` — a lower bound guaranteed by the
// sleep, so the test cannot flake. Before the fix, unknown and ineligible
// accounts answered in microseconds.
func TestAuthenticatorEveryAttemptTakesAVerification(t *testing.T) {
	t.Parallel()

	const delay = 25 * time.Millisecond

	for _, c := range attempts("real-hash") {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			a := basic.NewAuthenticator(c.loader(t), &recordingHasher{match: "real-hash", delay: delay})

			start := time.Now()
			_, err := a.Authenticate(context.Background(), basic.New("alice", c.password))
			elapsed := time.Since(start)

			require.Error(t, err)
			assert.GreaterOrEqual(t, elapsed, delay, "the attempt skipped the password verification")
		})
	}
}

// With the real hashers, unknown and known accounts answer in comparable
// time. To stay robust on a loaded machine, the accounts are interleaved in
// every round (drift — warm-up, GC debt, CPU frequency — affects them all
// alike) and the fastest of nine runs is compared: noise only ever adds
// time. Before the fix the ratio was about 0.0001; the bound is 0.5.
func TestAuthenticatorResponseTimeDoesNotRevealAccounts(t *testing.T) {
	for _, c := range []struct {
		name string
		h    password.Hasher
	}{
		{"bcrypt", password.NewBCryptHasher(6)},
		{"argon2id", password.NewArgon2idHasher(password.Argon2idParams{MemoryKiB: 4 * 1024, Time: 1, Parallelism: 1})},
	} {
		hash, err := c.h.Hash(context.Background(), "right")
		require.NoError(t, err)

		users := map[string]basic.PasswordUser{
			"alice":  mockUser(t, account{subject: "alice", hash: hash}),
			"locked": mockUser(t, account{subject: "locked", hash: hash, locked: true}),
		}
		loader := mockLoader(t, func(username string) (basic.PasswordUser, error) {
			if u, ok := users[username]; ok {
				return u, nil
			}

			return nil, security.ErrInvalidCredentials
		})

		a := basic.NewAuthenticator(loader, c.h)
		fastest := map[string]time.Duration{}

		for range 9 {
			for _, username := range []string{"alice", "nobody", "locked"} {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				start := time.Now()
				_, err := a.Authenticate(ctx, basic.New(username, "wrong"))
				d := time.Since(start)

				cancel()
				require.NotErrorIs(t, err, security.ErrUnavailable)

				if fastest[username] == 0 || d < fastest[username] {
					fastest[username] = d
				}
			}
		}

		for _, other := range []string{"nobody", "locked"} {
			ratio := float64(fastest[other]) / float64(fastest["alice"])
			assert.GreaterOrEqual(t, ratio, 0.5, "%s: %s answers %.3f× the time of a known account", c.name, other, ratio)
		}
	}
}

// The dummy hash is made by the configured hasher, with its current
// parameters: it costs what a stored hash at those parameters costs.
func TestNewAuthenticatorMakesTheDummyWithTheConfiguredHasher(t *testing.T) {
	t.Parallel()

	params := password.Argon2idParams{MemoryKiB: 1024, Time: 3, Parallelism: 2, KeyLen: 32, SaltLen: 16}
	rec := &recordingWrapper{Hasher: password.NewArgon2idHasher(params)}

	l := basic.NewMockUserLoader(t)
	l.EXPECT().LoadByUsername(mock.Anything, "nobody").Return(nil, nil).Once()
	a := basic.NewAuthenticator(l, rec)

	_, err := a.Authenticate(context.Background(), basic.New("nobody", "pw"))
	require.ErrorIs(t, err, security.ErrInvalidCredentials)

	require.Len(t, rec.verified, 1)
	assert.True(t, strings.HasPrefix(rec.verified[0], "$argon2id$v=19$m=1024,t=3,p=2$"), rec.verified[0])
}

// recordingWrapper records the hashes a real hasher verifies.
type recordingWrapper struct {
	password.Hasher

	mu       sync.Mutex
	verified []string
}

func (w *recordingWrapper) Verify(ctx context.Context, hash, pw string) (bool, error) {
	w.mu.Lock()
	w.verified = append(w.verified, hash)
	w.mu.Unlock()

	return w.Hasher.Verify(ctx, hash, pw) //nolint:wrapcheck // test fake
}

func TestNewAuthenticatorPanics(t *testing.T) {
	t.Parallel()

	loader := basic.NewMockUserLoader(t) // never called

	assert.PanicsWithValue(t, "basic: NewAuthenticator: nil UserLoader", func() {
		basic.NewAuthenticator(nil, &recordingHasher{})
	})
	assert.PanicsWithValue(t, "basic: NewAuthenticator: nil password.Hasher", func() {
		basic.NewAuthenticator(loader, nil)
	})
	assert.Panics(t, func() {
		basic.NewAuthenticator(loader, &recordingHasher{hashErr: errors.New("hsm offline")})
	}, "an Authenticator without its dummy hash would reopen the timing oracle")
}

// A stored hash the hasher cannot verify (malformed, another algorithm,
// above the cost limit) refuses the attempt with ErrInvalidCredentials, the
// cause kept for the server's logs.
func TestAuthenticatorRefusesAnUnverifiableStoredHash(t *testing.T) {
	t.Parallel()

	l := basic.NewMockUserLoader(t)
	l.EXPECT().LoadByUsername(mock.Anything, "alice").Return(mockUser(t, account{subject: "alice", hash: "$2a$broken"}), nil).Once()
	a := basic.NewAuthenticator(l, password.NewBCryptHasher(4))

	out, err := a.Authenticate(context.Background(), basic.New("alice", "right"))

	require.ErrorIs(t, err, security.ErrInvalidCredentials)
	require.ErrorIs(t, err, password.ErrMalformedHash)
	assert.False(t, out.IsAuthenticated())
}
