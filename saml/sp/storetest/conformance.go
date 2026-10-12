// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package storetest provides the black-box conformance suite every
// [samlsp.Storage] implementation MUST pass. The in-memory, SQL and Redis
// stores all run RunConformance against fresh instances, so behavioral
// drift between backends is caught at test time.
//
// The package imports "testing" deliberately: it is a test helper in the
// spirit of net/http/httptest, meant to be called from _test.go files.
package storetest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	samlsp "github.com/hyperscale-stack/security/saml/sp"
)

// Factory builds a fresh, empty store. RunConformance calls it once per
// sub-test so cases never share state.
type Factory func() samlsp.Storage

// RunConformance executes the storage contract stated on
// [samlsp.TransactionStore] and [samlsp.ReplayCache] against the stores
// produced by newStore: exact round trips (Integrity included), single
// consumption, the error
// precedence, a binding mismatch that consumes nothing, insert-if-absent
// saves and replay marks, input validation before I/O, retention until
// expiry, and the atomicity of consumption, saves and replay marks under
// 50-goroutine races. Purging after expiry is optional for stores and is
// therefore left to each store's own tests.
func RunConformance(t *testing.T, newStore Factory) {
	t.Helper()

	cases := []struct {
		name string
		run  func(*testing.T, samlsp.Storage)
	}{
		{"TransactionSaveLookupConsume", testSaveLookupConsume},
		{"TransactionSingleUse", testSingleUse},
		{"TransactionUnknown", testUnknown},
		{"TransactionBindingMismatchDoesNotConsume", testBindingMismatch},
		{"TransactionConsumedPrecedesBindingMismatch", testConsumedPrecedence},
		{"TransactionDuplicateSave", testDuplicateSave},
		{"TransactionIdenticalDuplicateSave", testIdenticalDuplicateSave},
		{"TransactionRejectsInvalidRecord", testRejectsInvalidRecord},
		{"TransactionRejectsInvalidKeys", testRejectsInvalidKeys},
		{"TransactionLookupNeverConsumes", testLookupNeverConsumes},
		{"TransactionIsolation", testIsolation},
		{"TransactionRetainedUntilExpiry", testRetainedUntilExpiry},
		{"TransactionConcurrentConsume", testConcurrentConsume},
		{"TransactionConcurrentMixedBinding", testConcurrentMixedBinding},
		{"TransactionConcurrentSave", testConcurrentSave},
		{"ReplayMarkOnce", testReplayMarkOnce},
		{"ReplayIndependentKeys", testReplayIndependentKeys},
		{"ReplayRejectsInvalidInput", testReplayRejectsInvalidInput},
		{"ReplayConcurrentMark", testReplayConcurrentMark},
		{"NamespacesIsolated", testNamespacesIsolated},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.run(t, newStore())
		})
	}
}

// racers is the number of goroutines of every race case.
const racers = 50

func ctx() context.Context { return context.Background() }

// key derives a valid 64-hex store key from a label.
func key(label string) string {
	sum := sha256.Sum256([]byte(label))

	return hex.EncodeToString(sum[:])
}

// expiry returns a whole-second expiry in the future: the suite runs against
// stores that purge by wall clock (Redis TTLs), so it must not be in the past.
func expiry() time.Time {
	return time.Now().Add(10 * time.Minute).Truncate(time.Second)
}

// record returns a valid record labeled label.
func record(label string) *samlsp.TransactionRecord {
	return &samlsp.TransactionRecord{
		ID:          key("tx/" + label),
		BindingHash: key("binding/" + label),
		Integrity:   key("integrity/" + label),
		Payload:     `{"v":1,"label":"` + label + `","escaped":"\u00e9\u2713"}`,
		ExpiresAt:   expiry(),
	}
}

// The assertion helpers hold every t.Fatalf of the suite.

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

func mustEqualRecord(t *testing.T, got, want *samlsp.TransactionRecord, msg string) {
	t.Helper()

	if got == nil {
		t.Fatalf("%s: got a nil record", msg)
	}

	if got.ID != want.ID || got.BindingHash != want.BindingHash || got.Payload != want.Payload ||
		!got.ExpiresAt.Equal(want.ExpiresAt) || got.Integrity != want.Integrity {
		t.Fatalf("%s: got %+v, want %+v", msg, *got, *want)
	}
}

func mustCount(t *testing.T, got, want int, msg string) {
	t.Helper()

	if got != want {
		t.Fatalf("%s: got %d, want %d", msg, got, want)
	}
}

func save(t *testing.T, s samlsp.Storage, rec *samlsp.TransactionRecord) {
	t.Helper()

	mustNoError(t, s.SaveTransaction(ctx(), rec), "SaveTransaction")
}

// race runs fn on racers goroutines released together and returns the
// errors in no particular order.
func race(fn func(i int) error) []error {
	var (
		start sync.WaitGroup
		done  sync.WaitGroup
		mu    sync.Mutex
		errs  = make([]error, 0, racers)
	)

	record := func(err error) {
		mu.Lock()
		defer mu.Unlock()

		errs = append(errs, err)
	}

	start.Add(1)

	for i := 0; i < racers; i++ {
		done.Add(1)

		go func(i int) {
			defer done.Done()

			start.Wait()
			record(fn(i))
		}(i)
	}

	start.Done()
	done.Wait()

	return errs
}

// countOutcomes classifies race results: nil, then each listed sentinel; any
// other error fails the test.
func countOutcomes(t *testing.T, errs []error, sentinels ...error) (successes int, counts []int) {
	t.Helper()

	counts = make([]int, len(sentinels))

	for _, err := range errs {
		if err == nil {
			successes++

			continue
		}

		matched := false

		for i, s := range sentinels {
			if errors.Is(err, s) {
				counts[i]++
				matched = true

				break
			}
		}

		if !matched {
			t.Fatalf("race: unexpected error %v", err)
		}
	}

	return successes, counts
}

func testSaveLookupConsume(t *testing.T, s samlsp.Storage) {
	rec := record("round-trip")
	save(t, s, rec)

	got, err := s.LookupTransaction(ctx(), rec.ID)
	mustNoError(t, err, "LookupTransaction")
	mustEqualRecord(t, got, rec, "LookupTransaction")

	mustNoError(t, s.ConsumeTransaction(ctx(), rec.ID, rec.BindingHash), "ConsumeTransaction")

	_, err = s.LookupTransaction(ctx(), rec.ID)
	mustErrorIs(t, err, samlsp.ErrTransactionConsumed, "LookupTransaction after consume")
}

func testSingleUse(t *testing.T, s samlsp.Storage) {
	rec := record("single-use")
	save(t, s, rec)

	mustNoError(t, s.ConsumeTransaction(ctx(), rec.ID, rec.BindingHash), "first consume")

	err := s.ConsumeTransaction(ctx(), rec.ID, rec.BindingHash)
	mustErrorIs(t, err, samlsp.ErrTransactionConsumed, "second consume")
	mustErrorIs(t, err, samlsp.ErrRejected, "second consume")
}

func testUnknown(t *testing.T, s samlsp.Storage) {
	_, err := s.LookupTransaction(ctx(), key("unknown"))
	mustErrorIs(t, err, samlsp.ErrTransactionNotFound, "LookupTransaction unknown")

	err = s.ConsumeTransaction(ctx(), key("unknown"), key("binding"))
	mustErrorIs(t, err, samlsp.ErrTransactionNotFound, "ConsumeTransaction unknown")
}

func testBindingMismatch(t *testing.T, s samlsp.Storage) {
	rec := record("binding")
	save(t, s, rec)

	err := s.ConsumeTransaction(ctx(), rec.ID, key("another browser"))
	mustErrorIs(t, err, samlsp.ErrBrowserBindingMismatch, "consume with another binding")

	got, err := s.LookupTransaction(ctx(), rec.ID)
	mustNoError(t, err, "lookup after mismatch")
	mustEqualRecord(t, got, rec, "lookup after mismatch")

	mustNoError(t, s.ConsumeTransaction(ctx(), rec.ID, rec.BindingHash), "consume with the right binding")
}

func testConsumedPrecedence(t *testing.T, s samlsp.Storage) {
	rec := record("precedence")
	save(t, s, rec)
	mustNoError(t, s.ConsumeTransaction(ctx(), rec.ID, rec.BindingHash), "consume")

	err := s.ConsumeTransaction(ctx(), rec.ID, key("another browser"))
	mustErrorIs(t, err, samlsp.ErrTransactionConsumed, "consumed record with another binding")
}

func testDuplicateSave(t *testing.T, s samlsp.Storage) {
	rec := record("duplicate")
	save(t, s, rec)

	other := *rec
	other.BindingHash = key("intruder")
	other.Payload = `{"v":1,"label":"intruder"}`
	other.Integrity = key("intruder integrity")

	err := s.SaveTransaction(ctx(), &other)
	mustErrorIs(t, err, samlsp.ErrTransactionExists, "second save with the same ID")

	got, err := s.LookupTransaction(ctx(), rec.ID)
	mustNoError(t, err, "lookup after duplicate save")
	mustEqualRecord(t, got, rec, "the original record must be intact")
}

// testIdenticalDuplicateSave: an existing ID is never saved again, even by
// a call with identical content, consumed or not; only a resend of the very
// same call may be recognized as its own success.
func testIdenticalDuplicateSave(t *testing.T, s samlsp.Storage) {
	rec := record("identical")
	save(t, s, rec)

	again := *rec
	mustErrorIs(t, s.SaveTransaction(ctx(), &again), samlsp.ErrTransactionExists, "identical second save")

	mustNoError(t, s.ConsumeTransaction(ctx(), rec.ID, rec.BindingHash), "consume")

	again = *rec
	mustErrorIs(t, s.SaveTransaction(ctx(), &again), samlsp.ErrTransactionExists, "identical save of a consumed record")

	_, err := s.LookupTransaction(ctx(), rec.ID)
	mustErrorIs(t, err, samlsp.ErrTransactionConsumed, "the consumed record stays consumed")
}

func testRejectsInvalidRecord(t *testing.T, s samlsp.Storage) {
	valid := record("invalid")

	mutations := []struct {
		name   string
		mutate func(*samlsp.TransactionRecord)
	}{
		{"short ID", func(r *samlsp.TransactionRecord) { r.ID = r.ID[:63] }},
		{"uppercase ID", func(r *samlsp.TransactionRecord) { r.ID = strings.ToUpper(r.ID) }},
		{"bad binding", func(r *samlsp.TransactionRecord) { r.BindingHash = "zz" + r.BindingHash[2:] }},
		{"empty integrity", func(r *samlsp.TransactionRecord) { r.Integrity = "" }},
		{"upper-case integrity", func(r *samlsp.TransactionRecord) { r.Integrity = strings.ToUpper(r.Integrity) }},
		{"short integrity", func(r *samlsp.TransactionRecord) { r.Integrity = r.Integrity[:63] }},
		{"empty payload", func(r *samlsp.TransactionRecord) { r.Payload = "" }},
		{"oversized payload", func(r *samlsp.TransactionRecord) {
			r.Payload = strings.Repeat("x", samlsp.MaxTransactionPayloadSize+1)
		}},
		{"NUL in payload", func(r *samlsp.TransactionRecord) { r.Payload = "a\x00b" }},
		{"invalid UTF-8 payload", func(r *samlsp.TransactionRecord) { r.Payload = "a\xffb" }},
		{"non-ASCII payload", func(r *samlsp.TransactionRecord) { r.Payload = "{\"app\":\"\u00e9\"}" }},
		{"zero expiry", func(r *samlsp.TransactionRecord) { r.ExpiresAt = time.Time{} }},
		{"sub-second expiry", func(r *samlsp.TransactionRecord) { r.ExpiresAt = r.ExpiresAt.Add(time.Millisecond) }},
	}

	for _, m := range mutations {
		rec := *valid
		m.mutate(&rec)

		err := s.SaveTransaction(ctx(), &rec)
		mustErrorIs(t, err, samlsp.ErrInvalidStoreRecord, "save "+m.name)
	}

	mustErrorIs(t, s.SaveTransaction(ctx(), nil), samlsp.ErrInvalidStoreRecord, "save nil")

	// Nothing was persisted: the valid record can still be saved.
	save(t, s, valid)
}

func testRejectsInvalidKeys(t *testing.T, s samlsp.Storage) {
	_, err := s.LookupTransaction(ctx(), "not-a-key")
	mustErrorIs(t, err, samlsp.ErrInvalidStoreRecord, "lookup with an invalid ID")

	err = s.ConsumeTransaction(ctx(), "not-a-key", key("binding"))
	mustErrorIs(t, err, samlsp.ErrInvalidStoreRecord, "consume with an invalid ID")

	err = s.ConsumeTransaction(ctx(), key("tx"), "not-a-hash")
	mustErrorIs(t, err, samlsp.ErrInvalidStoreRecord, "consume with an invalid binding")
}

func testLookupNeverConsumes(t *testing.T, s samlsp.Storage) {
	rec := record("lookups")
	save(t, s, rec)

	for i := 0; i < 3; i++ {
		got, err := s.LookupTransaction(ctx(), rec.ID)
		mustNoError(t, err, "repeated lookup")
		mustEqualRecord(t, got, rec, "repeated lookup")
	}

	mustNoError(t, s.ConsumeTransaction(ctx(), rec.ID, rec.BindingHash), "consume after lookups")
}

func testIsolation(t *testing.T, s samlsp.Storage) {
	a, b := record("a"), record("b")
	save(t, s, a)
	save(t, s, b)

	mustNoError(t, s.ConsumeTransaction(ctx(), a.ID, a.BindingHash), "consume a")

	got, err := s.LookupTransaction(ctx(), b.ID)
	mustNoError(t, err, "b untouched")
	mustEqualRecord(t, got, b, "b untouched")

	mustErrorIs(t, s.ConsumeTransaction(ctx(), b.ID, a.BindingHash), samlsp.ErrBrowserBindingMismatch,
		"a's binding does not open b")
	mustNoError(t, s.ConsumeTransaction(ctx(), b.ID, b.BindingHash), "consume b")
}

func testRetainedUntilExpiry(t *testing.T, s samlsp.Storage) {
	rec := record("retained")
	rec.ExpiresAt = time.Now().Add(3 * time.Second).Truncate(time.Second).Add(time.Second)
	save(t, s, rec)

	got, err := s.LookupTransaction(ctx(), rec.ID)
	mustNoError(t, err, "lookup before expiry")
	mustEqualRecord(t, got, rec, "lookup before expiry: ExpiresAt round-trips exactly")

	mustNoError(t, s.ConsumeTransaction(ctx(), rec.ID, rec.BindingHash), "consume before expiry")

	mustErrorIs(t, s.ConsumeTransaction(ctx(), rec.ID, rec.BindingHash), samlsp.ErrTransactionConsumed,
		"the consumed record is retained before its expiry")
}

func testConcurrentConsume(t *testing.T, s samlsp.Storage) {
	rec := record("race")
	save(t, s, rec)

	errs := race(func(int) error { return s.ConsumeTransaction(ctx(), rec.ID, rec.BindingHash) })

	successes, counts := countOutcomes(t, errs, samlsp.ErrTransactionConsumed)
	mustCount(t, successes, 1, "concurrent consumers that succeeded")
	mustCount(t, counts[0], racers-1, "concurrent consumers told the transaction was consumed")
}

func testConcurrentMixedBinding(t *testing.T, s samlsp.Storage) {
	rec := record("mixed")
	save(t, s, rec)

	wrong := key("attacker")

	errs := race(func(i int) error {
		if i%2 == 0 {
			return s.ConsumeTransaction(ctx(), rec.ID, wrong)
		}

		return s.ConsumeTransaction(ctx(), rec.ID, rec.BindingHash)
	})

	successes, _ := countOutcomes(t, errs, samlsp.ErrTransactionConsumed, samlsp.ErrBrowserBindingMismatch)
	mustCount(t, successes, 1, "consumers that succeeded")
}

func testConcurrentSave(t *testing.T, s samlsp.Storage) {
	base := record("concurrent-save")

	errs := race(func(i int) error {
		rec := *base
		rec.Payload = fmt.Sprintf(`{"v":1,"writer":%d}`, i)

		return s.SaveTransaction(ctx(), &rec)
	})

	successes, counts := countOutcomes(t, errs, samlsp.ErrTransactionExists)
	mustCount(t, successes, 1, "concurrent saves that succeeded")
	mustCount(t, counts[0], racers-1, "concurrent saves told the transaction exists")
}

func testReplayMarkOnce(t *testing.T, s samlsp.Storage) {
	k := key("assertion")

	mustNoError(t, s.MarkAssertionUsed(ctx(), k, expiry()), "first mark")

	err := s.MarkAssertionUsed(ctx(), k, expiry())
	mustErrorIs(t, err, samlsp.ErrAssertionReplayed, "second mark")
	mustErrorIs(t, err, samlsp.ErrRejected, "second mark")
}

func testReplayIndependentKeys(t *testing.T, s samlsp.Storage) {
	mustNoError(t, s.MarkAssertionUsed(ctx(), key("one"), expiry()), "mark one")
	mustNoError(t, s.MarkAssertionUsed(ctx(), key("two"), expiry()), "mark two")
	mustErrorIs(t, s.MarkAssertionUsed(ctx(), key("one"), expiry()), samlsp.ErrAssertionReplayed, "remark one")
}

func testReplayRejectsInvalidInput(t *testing.T, s samlsp.Storage) {
	mustErrorIs(t, s.MarkAssertionUsed(ctx(), "nope", expiry()), samlsp.ErrInvalidStoreRecord, "invalid key")
	mustErrorIs(t, s.MarkAssertionUsed(ctx(), key("k"), time.Time{}), samlsp.ErrInvalidStoreRecord, "zero expiry")
	mustErrorIs(t, s.MarkAssertionUsed(ctx(), key("k"), expiry().Add(time.Millisecond)),
		samlsp.ErrInvalidStoreRecord, "sub-second expiry")

	// Nothing was recorded by the refused calls.
	mustNoError(t, s.MarkAssertionUsed(ctx(), key("k"), expiry()), "valid mark after refusals")
}

func testReplayConcurrentMark(t *testing.T, s samlsp.Storage) {
	k := key("raced assertion")
	exp := expiry()

	errs := race(func(int) error { return s.MarkAssertionUsed(ctx(), k, exp) })

	successes, counts := countOutcomes(t, errs, samlsp.ErrAssertionReplayed)
	mustCount(t, successes, 1, "concurrent marks that succeeded")
	mustCount(t, counts[0], racers-1, "concurrent marks reported as replays")
}

func testNamespacesIsolated(t *testing.T, s samlsp.Storage) {
	shared := key("shared")

	mustNoError(t, s.MarkAssertionUsed(ctx(), shared, expiry()), "mark a key")

	rec := record("namespaces")
	rec.ID = shared
	save(t, s, rec)
	mustNoError(t, s.ConsumeTransaction(ctx(), shared, rec.BindingHash), "a transaction with the same value")
	mustErrorIs(t, s.MarkAssertionUsed(ctx(), shared, expiry()), samlsp.ErrAssertionReplayed,
		"the replay entry is unaffected by the transaction")
}
