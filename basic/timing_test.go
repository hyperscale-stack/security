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
	"github.com/stretchr/testify/require"
)

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

// funcLoader is a basic.UserLoader driven by a function.
type funcLoader func(username string) (basic.PasswordUser, error)

func (f funcLoader) LoadByUsername(_ context.Context, username string) (basic.PasswordUser, error) {
	return f(username)
}

// attempts lists every outcome an attacker could tell apart by timing.
func attempts(real string) []struct {
	name     string
	loader   funcLoader
	password string
	dummy    bool // verified against the dummy hash
} {
	user := func(mod func(*stubUser)) funcLoader {
		return func(string) (basic.PasswordUser, error) {
			u := &stubUser{subject: "alice", passwordHash: real, enabled: true}
			mod(u)

			return u, nil
		}
	}

	return []struct {
		name     string
		loader   funcLoader
		password string
		dummy    bool
	}{
		{"unknown user (nil, nil)", func(string) (basic.PasswordUser, error) { return nil, nil }, "right", true},
		{"unknown user (ErrInvalidCredentials)", func(string) (basic.PasswordUser, error) {
			return nil, security.ErrInvalidCredentials
		}, "right", true},
		{"loader failure", func(string) (basic.PasswordUser, error) { return nil, errors.New("store down") }, "right", true},
		{"account without a password hash", user(func(u *stubUser) { u.passwordHash = "" }), "right", true},
		{"disabled", user(func(u *stubUser) { u.enabled = false }), "right", false},
		{"locked", user(func(u *stubUser) { u.locked = true }), "right", false},
		{"expired", user(func(u *stubUser) { u.expired = true }), "right", false},
		{"credentials expired", user(func(u *stubUser) { u.credentialsExpired = true }), "right", false},
		{"wrong password", user(func(*stubUser) {}), "wrong", false},
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
			a := basic.NewAuthenticator(c.loader, h)

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
			a := basic.NewAuthenticator(c.loader, h)

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
	locked := &stubUser{subject: "alice", passwordHash: "real-hash", enabled: true, locked: true}
	a := basic.NewAuthenticator(&stubLoader{user: locked}, h)

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

			a := basic.NewAuthenticator(c.loader, &recordingHasher{match: "real-hash", delay: delay})

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

		users := map[string]*stubUser{
			"alice":  {subject: "alice", passwordHash: hash, enabled: true},
			"locked": {subject: "locked", passwordHash: hash, enabled: true, locked: true},
		}
		loader := funcLoader(func(username string) (basic.PasswordUser, error) {
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

	a := basic.NewAuthenticator(funcLoader(func(string) (basic.PasswordUser, error) { return nil, nil }), rec)

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

	loader := funcLoader(func(string) (basic.PasswordUser, error) { return nil, nil })

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

	user := &stubUser{subject: "alice", passwordHash: "$2a$broken", enabled: true}
	a := basic.NewAuthenticator(&stubLoader{user: user}, password.NewBCryptHasher(4))

	out, err := a.Authenticate(context.Background(), basic.New("alice", "right"))

	require.ErrorIs(t, err, security.ErrInvalidCredentials)
	require.ErrorIs(t, err, password.ErrMalformedHash)
	assert.False(t, out.IsAuthenticated())
}
