// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package memory ships an in-process [samlsp.Storage] for development and
// tests. Production deployments with more than one instance MUST use the
// SQL or Redis stores: this one keeps its state in the process and loses it
// on restart.
//
// Expired records — transactions and replay marks past their expiry — are
// swept every 64 writes once one may have expired, on the store's clock
// ([WithClock], time.Now by default): give it the ServiceProvider's clock
// (samlsp.Config.Now) when that is not time.Now. The store then stays
// bounded by the login rate times the TransactionTTL; BeginLogin is
// unauthenticated, so rate-limit it. Sweeping never makes a login usable
// twice: a record is deleted only once the ServiceProvider refuses it as
// expired, a replayed response then finds no transaction
// (ErrTransactionNotFound), and an assertion's replay mark outlives the
// last instant it could be accepted.
//
// One mutex guards every operation, which makes consumption and replay
// marks trivially atomic.
package memory

import (
	"context"
	"crypto/subtle"
	"fmt"
	"sync"
	"time"

	samlsp "github.com/hyperscale-stack/security/saml/sp"
)

// sweepEvery is the number of writes between two sweeps of the expired
// records.
const sweepEvery = 64

// Option configures a [Store].
type Option func(*Store)

// WithClock sets the clock the store compares expiries with when it sweeps
// (time.Now by default): pass the ServiceProvider's clock. It panics on a
// nil clock.
func WithClock(now func() time.Time) Option {
	if now == nil {
		panic("memory: WithClock: nil clock")
	}

	return func(s *Store) { s.now = now }
}

// Store is an in-memory [samlsp.Storage]. Build one with [New].
type Store struct {
	now func() time.Time

	mu     sync.Mutex
	txs    map[string]entry
	used   map[string]time.Time
	writes int
	// nextExpiry is never after the earliest expiry stored (transactions
	// and replay marks alike) and zero for an empty store: until then, no
	// record can have expired.
	nextExpiry time.Time
	sweeps     int // the walks of the records, for the tests
}

// entry is a stored transaction and its consumption flag.
type entry struct {
	rec      samlsp.TransactionRecord
	consumed bool
}

// New returns an empty [Store].
func New(opts ...Option) *Store {
	s := &Store{
		now:  time.Now,
		txs:  make(map[string]entry),
		used: make(map[string]time.Time),
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// SaveTransaction implements [samlsp.TransactionStore]: it stores a copy
// of rec unless its ID exists.
func (s *Store) SaveTransaction(_ context.Context, rec *samlsp.TransactionRecord) error {
	if err := rec.Validate(); err != nil {
		return fmt.Errorf("memory: save transaction: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.maybeSweep()

	if _, ok := s.txs[rec.ID]; ok {
		return samlsp.ErrTransactionExists
	}

	s.txs[rec.ID] = entry{rec: *rec}
	s.noteExpiry(rec.ExpiresAt)

	return nil
}

// LookupTransaction implements [samlsp.TransactionStore].
func (s *Store) LookupTransaction(_ context.Context, id string) (*samlsp.TransactionRecord, error) {
	if err := samlsp.ValidateStoreKey(id); err != nil {
		return nil, fmt.Errorf("memory: lookup transaction: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.txs[id]

	switch {
	case !ok:
		return nil, samlsp.ErrTransactionNotFound
	case e.consumed:
		return nil, samlsp.ErrTransactionConsumed
	}

	rec := e.rec

	return &rec, nil
}

// ConsumeTransaction implements [samlsp.TransactionStore]; the store mutex
// is the linearization point.
func (s *Store) ConsumeTransaction(_ context.Context, id, bindingHash string) error {
	if err := samlsp.ValidateStoreKey(id); err != nil {
		return fmt.Errorf("memory: consume transaction: %w", err)
	}

	if err := samlsp.ValidateStoreKey(bindingHash); err != nil {
		return fmt.Errorf("memory: consume transaction: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.txs[id]

	switch {
	case !ok:
		return samlsp.ErrTransactionNotFound
	case e.consumed:
		return samlsp.ErrTransactionConsumed
	case subtle.ConstantTimeCompare([]byte(e.rec.BindingHash), []byte(bindingHash)) != 1:
		return samlsp.ErrBrowserBindingMismatch
	}

	e.consumed = true
	s.txs[id] = e

	return nil
}

// MarkAssertionUsed implements [samlsp.ReplayCache].
func (s *Store) MarkAssertionUsed(_ context.Context, key string, expiresAt time.Time) error {
	if err := samlsp.ValidateStoreKey(key); err != nil {
		return fmt.Errorf("memory: mark assertion: %w", err)
	}

	if err := samlsp.ValidateExpiry(expiresAt); err != nil {
		return fmt.Errorf("memory: mark assertion: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.maybeSweep()

	if _, ok := s.used[key]; ok {
		return samlsp.ErrAssertionReplayed
	}

	s.used[key] = expiresAt
	s.noteExpiry(expiresAt)

	return nil
}

// maybeSweep counts a write and, every sweepEvery writes, deletes the
// expired records. The caller holds the mutex.
func (s *Store) maybeSweep() {
	s.writes++
	if s.writes%sweepEvery != 0 {
		return
	}

	s.sweepExpired(s.now())
}

// sweepExpired deletes the records expired at now — expired at their
// expiry, as the ServiceProvider judges them — walking them only when one
// may have expired, and recomputes nextExpiry. The caller holds the mutex.
func (s *Store) sweepExpired(now time.Time) {
	if s.nextExpiry.IsZero() || now.Before(s.nextExpiry) {
		return
	}

	s.sweeps++
	s.nextExpiry = time.Time{}

	for id, e := range s.txs {
		if !now.Before(e.rec.ExpiresAt) {
			delete(s.txs, id)

			continue
		}

		s.noteExpiry(e.rec.ExpiresAt)
	}

	for key, exp := range s.used {
		if !now.Before(exp) {
			delete(s.used, key)

			continue
		}

		s.noteExpiry(exp)
	}
}

// noteExpiry keeps nextExpiry at or before t. The caller holds the mutex.
func (s *Store) noteExpiry(t time.Time) {
	if s.nextExpiry.IsZero() || t.Before(s.nextExpiry) {
		s.nextExpiry = t
	}
}
