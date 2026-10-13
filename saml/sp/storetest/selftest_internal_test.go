// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package storetest

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	samlsp "github.com/hyperscale-stack/security/saml/sp"
	"github.com/hyperscale-stack/security/saml/sp/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// maxFatalfArgs bounds the arguments of the suite's Fatalf calls: the
// generated mock matches variadic arguments one by one, so the recorder
// declares one expectation per count.
const maxFatalfArgs = 3

// newRecorder returns the generated mock of tester, recording the failure
// of a case and stopping it (runtime.Goexit) as testing.T.Fatalf would, so
// that the suite itself can be run against deliberately broken stores.
func newRecorder(t *testing.T, failure *string) *Mocktester {
	t.Helper()

	m := NewMocktester(t)
	m.EXPECT().Helper().Maybe()

	record := func(format string, args ...any) {
		*failure = fmt.Sprintf(format, args...)
		runtime.Goexit()
	}

	for n := 0; n <= maxFatalfArgs; n++ {
		args := make([]any, n)
		for i := range args {
			args[i] = mock.Anything
		}

		m.EXPECT().Fatalf(mock.Anything, args...).Run(record).Maybe()
	}

	return m
}

// caseTimeout bounds one case run through a recorder.
const caseTimeout = 30 * time.Second

// runRecorded runs every case of the suite on a fresh store and returns the
// failures by case name.
func runRecorded(t *testing.T, newStore func() samlsp.Storage) map[string]string {
	t.Helper()

	failures := map[string]string{}

	for _, c := range conformanceCases() {
		var failure string

		r := newRecorder(t, &failure)
		done := make(chan struct{})

		go func() {
			defer close(done)

			c.run(r, newStore())
		}()

		select {
		case <-done:
		case <-time.After(caseTimeout):
			t.Fatalf("case %s did not finish within %s", c.name, caseTimeout)
		}

		if failure != "" {
			failures[c.name] = failure
		}
	}

	return failures
}

// The flaws of flawedStore.
const (
	flawForgetsConsumptions = "forgets a consumption shortly after it"
	flawForgetsMarks        = "forgets a replay mark shortly after it"
	flawAcceptsIdentical    = "accepts an identical second save"
	flawDropsIntegrity      = "does not return Integrity"
	flawFailsPastExpiry     = "fails on a record past its expiry"
)

// errPastExpiry is the infrastructure error of flawFailsPastExpiry.
var errPastExpiry = errors.New("record past its expiry")

// forgetWindow is how long a forgetful flawedStore remembers: long enough
// for every immediate check of the suite, far shorter than retentionWait.
const forgetWindow = 100 * time.Millisecond

// flawedStore is the reference memory store with one flaw. It is written
// by hand: the generated samlsp mocks are in-package test files of samlsp,
// absent from this package's test binary, and the self-test must live here
// to reach conformanceCases.
type flawedStore struct {
	*memory.Store

	flaw string

	mu       sync.Mutex
	saved    map[string]samlsp.TransactionRecord
	consumed map[string]time.Time
	marked   map[string]time.Time
}

func newFlawedStore(flaw string) *flawedStore {
	return &flawedStore{
		Store: memory.New(), flaw: flaw,
		saved: map[string]samlsp.TransactionRecord{}, consumed: map[string]time.Time{}, marked: map[string]time.Time{},
	}
}

func (s *flawedStore) SaveTransaction(ctx context.Context, rec *samlsp.TransactionRecord) error {
	err := s.Store.SaveTransaction(ctx, rec)

	s.mu.Lock()
	defer s.mu.Unlock()

	switch {
	case err == nil:
		s.saved[rec.ID] = *rec
	case errors.Is(err, samlsp.ErrTransactionExists) && s.flaw == flawAcceptsIdentical && s.saved[rec.ID] == *rec:
		return nil
	}

	return err
}

func (s *flawedStore) LookupTransaction(ctx context.Context, id string) (*samlsp.TransactionRecord, error) {
	rec, err := s.Store.LookupTransaction(ctx, id)

	s.mu.Lock()
	defer s.mu.Unlock()

	switch {
	case err == nil && s.flaw == flawFailsPastExpiry && !time.Now().Before(rec.ExpiresAt):
		return nil, errPastExpiry
	case err == nil && s.flaw == flawDropsIntegrity:
		rec.Integrity = ""
	case errors.Is(err, samlsp.ErrTransactionConsumed) && s.forgotten(s.consumed, id, flawForgetsConsumptions):
		saved := s.saved[id]

		return &saved, nil
	}

	return rec, err
}

func (s *flawedStore) ConsumeTransaction(ctx context.Context, id, bindingHash string) error {
	err := s.Store.ConsumeTransaction(ctx, id, bindingHash)

	s.mu.Lock()
	defer s.mu.Unlock()

	switch {
	case err == nil:
		s.consumed[id] = time.Now()
	case errors.Is(err, samlsp.ErrTransactionConsumed) && s.forgotten(s.consumed, id, flawForgetsConsumptions):
		s.consumed[id] = time.Now()

		return nil
	}

	return err
}

func (s *flawedStore) MarkAssertionUsed(ctx context.Context, key string, expiresAt time.Time) error {
	err := s.Store.MarkAssertionUsed(ctx, key, expiresAt)

	s.mu.Lock()
	defer s.mu.Unlock()

	switch {
	case err == nil:
		s.marked[key] = time.Now()
	case errors.Is(err, samlsp.ErrAssertionReplayed) && s.forgotten(s.marked, key, flawForgetsMarks):
		s.marked[key] = time.Now()

		return nil
	}

	return err
}

// forgotten reports whether the store has the flaw and recorded key more
// than forgetWindow ago. The caller holds s.mu.
func (s *flawedStore) forgotten(at map[string]time.Time, key, flaw string) bool {
	recorded, ok := at[key]

	return s.flaw == flaw && ok && time.Since(recorded) > forgetWindow
}

// TestSuiteCatchesFlawedStores: every flaw below is caught by the named
// case of the suite. A store forgetting a consumption or a replay mark
// shortly after recording it passed every immediate check (audit SAML-03).
func TestSuiteCatchesFlawedStores(t *testing.T) {
	t.Parallel()

	for flaw, caughtBy := range map[string]string{
		flawForgetsConsumptions: "RetainedOverTime",
		flawForgetsMarks:        "RetainedOverTime",
		flawAcceptsIdentical:    "TransactionIdenticalDuplicateSave",
		flawDropsIntegrity:      "TransactionSaveLookupConsume",
		flawFailsPastExpiry:     "ExpiredRecords",
	} {
		t.Run(flaw, func(t *testing.T) {
			t.Parallel()

			failures := runRecorded(t, func() samlsp.Storage { return newFlawedStore(flaw) })
			assert.Contains(t, failures, caughtBy, "a store that %s must fail %s; failed cases: %v", flaw, caughtBy, failures)
		})
	}
}

// TestSuitePassesOnMemoryThroughTheRecorder: the recorder reports no
// failure for the reference store, so the flaws above are what fails.
func TestSuitePassesOnMemoryThroughTheRecorder(t *testing.T) {
	t.Parallel()

	require.Empty(t, runRecorded(t, func() samlsp.Storage { return memory.New() }))
}
