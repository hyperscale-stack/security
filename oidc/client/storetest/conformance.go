// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package storetest provides the black-box conformance suite every
// [oidcclient.TransactionStore] implementation MUST pass. The in-memory,
// SQL and Redis stores all run RunConformance against fresh instances, so
// behavioral drift between backends fails at test time.
//
// The package imports "testing" deliberately: it is a test helper in the
// spirit of net/http/httptest, meant to be called from _test.go files.
package storetest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	oidcclient "github.com/hyperscale-stack/security/oidc/client"
)

// Factory builds a fresh, empty store. RunConformance calls it once per
// case so cases never share state.
type Factory func() oidcclient.TransactionStore

// RunConformance runs the TransactionStore contract against the stores
// newStore builds: round trip of every field, Integrity included (boundary
// values included, timestamps returned in UTC), single consumption, the pinned decision
// order of Consume (unknown, expired whatever the binding, binding
// mismatch leaving the transaction stored), Save never overwriting,
// Validate enforced before any I/O, isolation, and atomic consumption
// under 50 concurrent consumers, with and without wrong bindings.
//
//	func TestMyStoreConformance(t *testing.T) {
//	    storetest.RunConformance(t, func() oidcclient.TransactionStore { return New(...) })
//	}
func RunConformance(t *testing.T, newStore Factory) {
	t.Helper()

	cases := []struct {
		name string
		run  func(*testing.T, oidcclient.TransactionStore)
	}{
		{"SaveConsumeRoundTrip", testRoundTrip},
		{"SaveConsumeBoundaryValues", testRoundTripBoundaries},
		{"ConsumeIsSingleUse", testSingleUse},
		{"ConsumeUnknown", testUnknown},
		{"BindingMismatchKeepsTransaction", testBindingMismatch},
		{"ExpiredIsNotFound", testExpired},
		{"ExpiryDecidedBeforeBinding", testExpiredWrongBinding},
		{"SaveNeverOverwrites", testSaveNeverOverwrites},
		{"SaveRefusesInvalid", testSaveInvalid},
		{"TransactionsAreIsolated", testIsolation},
		{"ConcurrentConsume", testConcurrentConsume},
		{"ConcurrentConsumeMixedBindings", testConcurrentMixedBindings},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.run(t, newStore())
		})
	}
}

// concurrency is the number of goroutines racing for one transaction.
const concurrency = 50

func ctx() context.Context { return context.Background() }

func hash(s string) string {
	sum := sha256.Sum256([]byte(s))

	return hex.EncodeToString(sum[:])
}

// sample returns a valid transaction, unique per seed, created now.
func sample(seed string) *oidcclient.Transaction {
	now := time.Unix(time.Now().Unix(), 0).UTC()

	return &oidcclient.Transaction{
		StateHash:    hash("state-" + seed),
		BindingHash:  hash("binding-" + seed),
		ConnectionID: "acme-okta",
		Issuer:       "https://idp.example.com/tenants/acme",
		ClientID:     "client-1",
		RedirectURI:  "https://rp.example.com/oidc/acme-okta/callback",
		ResponseMode: oidcclient.ResponseModeQuery,
		MaxAge:       oidcclient.NoMaxAge,
		CreatedAt:    now,
		ExpiresAt:    now.Add(10 * time.Minute),
		Integrity:    hash("integrity-" + seed),
	}
}

// normalized is tx as a conforming store returns it: whole seconds, UTC.
func normalized(tx oidcclient.Transaction) oidcclient.Transaction {
	tx.CreatedAt = time.Unix(tx.CreatedAt.Unix(), 0).UTC()
	tx.ExpiresAt = time.Unix(tx.ExpiresAt.Unix(), 0).UTC()

	return tx
}

// The assertion helpers below hold every t.Fatalf of the suite.

func mustNoError(t *testing.T, err error, msg string) {
	t.Helper()

	if err != nil {
		t.Fatalf("%s: unexpected error: %v", msg, err)
	}
}

func mustErrorIs(t *testing.T, err, target error, msg string) {
	t.Helper()

	if !errors.Is(err, target) {
		t.Fatalf("%s: got error %v, want one matching %v", msg, err, target)
	}
}

func mustTrue(t *testing.T, cond bool, msg string) {
	t.Helper()

	if !cond {
		t.Fatal(msg)
	}
}

func mustSave(t *testing.T, s oidcclient.TransactionStore, tx *oidcclient.Transaction) {
	t.Helper()

	mustNoError(t, s.Save(ctx(), tx), "Save")
}

// mustConsume consumes tx with its own binding before it expires and
// checks the record returned is tx.
func mustConsume(t *testing.T, s oidcclient.TransactionStore, tx *oidcclient.Transaction) {
	t.Helper()

	got, err := s.Consume(ctx(), tx.StateHash, tx.BindingHash, tx.CreatedAt)
	mustNoError(t, err, "Consume")
	mustTrue(t, got != nil, "Consume: nil transaction without an error")
	mustTrue(t, got.CreatedAt.Location() == time.UTC && got.ExpiresAt.Location() == time.UTC,
		"Consume: timestamps must be returned in UTC")

	if normalized(*got) != normalized(*tx) {
		t.Fatalf("Consume: got %+v, want %+v", *got, *tx)
	}
}

// mustNotFound asserts that consuming tx (with binding, at now) finds
// nothing.
func mustNotFound(t *testing.T, s oidcclient.TransactionStore, tx *oidcclient.Transaction, binding string, now time.Time, msg string) {
	t.Helper()

	got, err := s.Consume(ctx(), tx.StateHash, binding, now)
	mustErrorIs(t, err, oidcclient.ErrTransactionNotFound, msg)
	mustTrue(t, got == nil, msg+": no transaction returned with an error")
}

func testRoundTrip(t *testing.T, s oidcclient.TransactionStore) {
	tx := sample("round-trip")
	mustSave(t, s, tx)
	mustConsume(t, s, tx)
}

// testRoundTripBoundaries saves the largest values Validate accepts, so a
// store truncating or re-encoding a field (VARCHAR length, JSON
// re-encoding of numbers or multi-byte strings) fails.
func testRoundTripBoundaries(t *testing.T, s oidcclient.TransactionStore) {
	tx := sample("boundaries")
	tx.ConnectionID = strings.Repeat("c", 255)
	tx.Issuer = "https://idp.example.com/" + strings.Repeat("i", 2048-len("https://idp.example.com/"))
	tx.ClientID = "client id with spaces " + strings.Repeat("x", 2048-len("client id with spaces "))
	tx.RedirectURI = "https://rp.example.com/cb?tenant=acme&x=" + strings.Repeat("r", 2048-len("https://rp.example.com/cb?tenant=acme&x="))
	tx.ResponseMode = oidcclient.ResponseModeFormPost
	tx.MaxAge = 1<<31 - 1
	tx.ACRValues = "urn:acr:silver urn:acr:gold"
	tx.AppState = strings.Repeat("é", 2048) // 4096 bytes of two-byte UTF-8
	mustSave(t, s, tx)
	mustConsume(t, s, tx)

	zero := sample("max-age-zero")
	zero.MaxAge = 0 // max_age=0 differs from NoMaxAge and must survive
	mustSave(t, s, zero)
	mustConsume(t, s, zero)
}

func testSingleUse(t *testing.T, s oidcclient.TransactionStore) {
	tx := sample("single-use")
	mustSave(t, s, tx)
	mustConsume(t, s, tx)
	mustNotFound(t, s, tx, tx.BindingHash, tx.CreatedAt, "second Consume")
}

func testUnknown(t *testing.T, s oidcclient.TransactionStore) {
	tx := sample("never-saved")
	mustNotFound(t, s, tx, tx.BindingHash, tx.CreatedAt, "unknown transaction")
}

func testBindingMismatch(t *testing.T, s oidcclient.TransactionStore) {
	tx := sample("binding")
	mustSave(t, s, tx)

	got, err := s.Consume(ctx(), tx.StateHash, hash("another browser"), tx.CreatedAt)
	mustErrorIs(t, err, oidcclient.ErrBindingMismatch, "wrong binding")
	mustTrue(t, got == nil, "wrong binding: no transaction returned")

	mustConsume(t, s, tx) // still stored for the right browser
}

func testExpired(t *testing.T, s oidcclient.TransactionStore) {
	atExpiry := sample("at-expiry")
	mustSave(t, s, atExpiry)
	mustNotFound(t, s, atExpiry, atExpiry.BindingHash, atExpiry.ExpiresAt, "now == ExpiresAt is expired")

	justBefore := sample("just-before")
	mustSave(t, s, justBefore)

	got, err := s.Consume(ctx(), justBefore.StateHash, justBefore.BindingHash, justBefore.ExpiresAt.Add(-time.Second))
	mustNoError(t, err, "one second before ExpiresAt")
	mustTrue(t, got != nil && got.StateHash == justBefore.StateHash, "one second before ExpiresAt: the transaction")
}

func testExpiredWrongBinding(t *testing.T, s oidcclient.TransactionStore) {
	tx := sample("expired-wrong-binding")
	mustSave(t, s, tx)
	mustNotFound(t, s, tx, hash("another browser"), tx.ExpiresAt.Add(time.Second),
		"an expired transaction is not found, whatever the binding")
}

func testSaveNeverOverwrites(t *testing.T, s oidcclient.TransactionStore) {
	tx := sample("duplicate")
	mustSave(t, s, tx)

	clash := sample("duplicate")
	clash.BindingHash = hash("attacker binding")
	clash.ConnectionID = "attacker"
	clash.Integrity = hash("attacker integrity")
	mustErrorIs(t, s.Save(ctx(), clash), oidcclient.ErrTransactionExists, "Save of an existing state hash")

	mustConsume(t, s, tx) // the original, untouched
}

func testSaveInvalid(t *testing.T, s oidcclient.TransactionStore) {
	cases := map[string]func(*oidcclient.Transaction){
		"short state hash":        func(tx *oidcclient.Transaction) { tx.StateHash = "abc" },
		"upper-case state hash":   func(tx *oidcclient.Transaction) { tx.StateHash = strings.ToUpper(tx.StateHash) },
		"empty binding hash":      func(tx *oidcclient.Transaction) { tx.BindingHash = "" },
		"empty integrity":         func(tx *oidcclient.Transaction) { tx.Integrity = "" },
		"upper-case integrity":    func(tx *oidcclient.Transaction) { tx.Integrity = strings.ToUpper(tx.Integrity) },
		"empty connection":        func(tx *oidcclient.Transaction) { tx.ConnectionID = "" },
		"connection with space":   func(tx *oidcclient.Transaction) { tx.ConnectionID = "acme okta" },
		"long connection":         func(tx *oidcclient.Transaction) { tx.ConnectionID = strings.Repeat("c", 256) },
		"empty issuer":            func(tx *oidcclient.Transaction) { tx.Issuer = "" },
		"long issuer":             func(tx *oidcclient.Transaction) { tx.Issuer = strings.Repeat("i", 2049) },
		"empty client":            func(tx *oidcclient.Transaction) { tx.ClientID = "" },
		"client with control":     func(tx *oidcclient.Transaction) { tx.ClientID = "client\n1" },
		"empty redirect":          func(tx *oidcclient.Transaction) { tx.RedirectURI = "" },
		"unknown response mode":   func(tx *oidcclient.Transaction) { tx.ResponseMode = "fragment" },
		"negative max age":        func(tx *oidcclient.Transaction) { tx.MaxAge = -2 },
		"huge max age":            func(tx *oidcclient.Transaction) { tx.MaxAge = 1 << 31 },
		"long acr values":         func(tx *oidcclient.Transaction) { tx.ACRValues = strings.Repeat("a", 2049) },
		"long app state":          func(tx *oidcclient.Transaction) { tx.AppState = strings.Repeat("a", 4097) },
		"invalid UTF-8 app state": func(tx *oidcclient.Transaction) { tx.AppState = "\xff" },
		"zero creation":           func(tx *oidcclient.Transaction) { tx.CreatedAt = time.Time{} },
		"expiry before creation":  func(tx *oidcclient.Transaction) { tx.ExpiresAt = tx.CreatedAt },
		"sub-second creation":     func(tx *oidcclient.Transaction) { tx.CreatedAt = tx.CreatedAt.Add(time.Millisecond) },
	}

	for name, breakIt := range cases {
		tx := sample("invalid-" + name)
		breakIt(tx)
		mustErrorIs(t, s.Save(ctx(), tx), oidcclient.ErrInvalidTransaction, "Save of a transaction with "+name)

		if len(tx.StateHash) == 64 {
			valid := sample("invalid-" + name)
			mustNotFound(t, s, valid, valid.BindingHash, valid.CreatedAt, "nothing stored for "+name)
		}
	}

	mustErrorIs(t, s.Save(ctx(), nil), oidcclient.ErrInvalidTransaction, "Save(nil)")
}

func testIsolation(t *testing.T, s oidcclient.TransactionStore) {
	a, b := sample("isolation-a"), sample("isolation-b")
	mustSave(t, s, a)
	mustSave(t, s, b)

	got, err := s.Consume(ctx(), a.StateHash, b.BindingHash, a.CreatedAt)
	mustErrorIs(t, err, oidcclient.ErrBindingMismatch, "a's state with b's binding")
	mustTrue(t, got == nil, "no transaction returned")

	mustConsume(t, s, a)
	mustConsume(t, s, b)
}

// race starts n goroutines calling Consume with the bindings returned by
// bindingOf, released together, and returns how many got the transaction
// and every error.
func race(s oidcclient.TransactionStore, tx *oidcclient.Transaction, n int, bindingOf func(int) string) (int, []error) {
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		winners int
		errs    = make([]error, n)
		start   = make(chan struct{})
	)

	for i := range n {
		wg.Add(1)

		go func() {
			defer wg.Done()

			<-start

			got, err := s.Consume(ctx(), tx.StateHash, bindingOf(i), tx.CreatedAt)
			errs[i] = err

			if err == nil && got != nil {
				mu.Lock()
				winners++
				mu.Unlock()
			}
		}()
	}

	close(start)
	wg.Wait()

	return winners, errs
}

func testConcurrentConsume(t *testing.T, s oidcclient.TransactionStore) {
	tx := sample("race")
	mustSave(t, s, tx)

	winners, errs := race(s, tx, concurrency, func(int) string { return tx.BindingHash })
	mustTrue(t, winners == 1, "exactly one concurrent consumer must win")

	losers := 0

	for _, err := range errs {
		if err != nil {
			mustErrorIs(t, err, oidcclient.ErrTransactionNotFound, "a concurrent loser")

			losers++
		}
	}

	mustTrue(t, losers == concurrency-1, "every other consumer must get ErrTransactionNotFound")
}

func testConcurrentMixedBindings(t *testing.T, s oidcclient.TransactionStore) {
	tx := sample("race-mixed")
	mustSave(t, s, tx)

	wrong := hash("attacker binding")
	bindingOf := func(i int) string {
		if i%2 == 0 {
			return wrong
		}

		return tx.BindingHash
	}

	winners, errs := race(s, tx, concurrency, bindingOf)
	mustTrue(t, winners == 1, "exactly one right-binding consumer must win")

	for i, err := range errs {
		if bindingOf(i) == wrong {
			mustTrue(t, err != nil, "a wrong binding never wins")
			mustTrue(t, errors.Is(err, oidcclient.ErrBindingMismatch) || errors.Is(err, oidcclient.ErrTransactionNotFound),
				"a wrong binding gets ErrBindingMismatch, or ErrTransactionNotFound once consumed")
		}
	}
}
