// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package memory ships an in-process oidcclient.TransactionStore for
// development, tests and single-instance deployments. Its transactions
// live in the process: they are lost on restart and invisible to other
// instances, so a deployment with several instances behind a load balancer
// MUST use a shared store (oidc/client/store/sql or oidc/client/store/redis).
//
// Expired transactions — abandoned logins — are swept every 64 operations
// once one may have expired. Login starts are unauthenticated: the store
// keeps at most DefaultCapacity live transactions — WithCapacity sets
// another bound — and refuses the next with ErrFull, so that a flood of
// starts cannot exhaust the process's memory; rate-limit them too, since a
// full store fails every new login until transactions expire. One mutex
// serializes every operation; it is the linearization point of the
// single-consumption guarantee.
package memory

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"
	"time"

	oidcclient "github.com/hyperscale-stack/security/oidc/client"
)

// ErrFull reports a Save refused because the store holds its capacity of
// transactions (DefaultCapacity, or WithCapacity): the login fails to
// start; no pending login is evicted to make room.
var ErrFull = errors.New("memory: transaction store full")

// DefaultCapacity is the number of live transactions a Store built without
// WithCapacity keeps: 10 000 pending logins — about 16 login starts a
// second over the default 10-minute TransactionTTL, 2.8 over the maximum
// of one hour — about 46 MB with 4 KiB AppStates, more with long
// acr_values (up to about 66 MB).
const DefaultCapacity = 10_000

// Option configures a Store.
type Option func(*Store)

// WithCapacity bounds the transactions the store retains to n instead of
// DefaultCapacity, at least 1: it panics otherwise, so that a bound
// computed as zero never silently disables itself. At capacity, Save first drops the expired transactions,
// then refuses with ErrFull; a pending login is never evicted. A full store
// refuses in constant time — it walks its transactions at most once per
// expiry, not once per refused login. Size it from the login rate and the
// transaction TTL (about 0.5 KB per transaction, plus its AppState of up to
// 4 KiB), and rate-limit login starts: a full store fails every new login
// until transactions expire or are consumed.
func WithCapacity(n int) Option {
	if n < 1 {
		panic("memory: WithCapacity: the capacity must be at least 1")
	}

	return func(s *Store) { s.capacity = n }
}

// sweepEvery is the number of operations between two sweeps of the
// expired transactions.
const sweepEvery = 64

// Store is an in-memory oidcclient.TransactionStore, safe for concurrent
// use. The zero value is unusable; build one with New.
type Store struct {
	capacity int

	mu  sync.Mutex
	txs map[string]oidcclient.Transaction
	ops int
	// nextExpiry is never after the earliest ExpiresAt stored — it may be
	// earlier once that transaction is consumed — and zero for an empty
	// store: until then, no transaction can have expired.
	nextExpiry time.Time
	sweeps     int // the walks of txs, for the tests
}

// New returns an empty Store keeping at most DefaultCapacity transactions,
// unless WithCapacity says otherwise.
func New(opts ...Option) *Store {
	s := &Store{capacity: DefaultCapacity, txs: make(map[string]oidcclient.Transaction)}
	for _, opt := range opts {
		opt(s)
	}

	return s
}

// Save implements oidcclient.TransactionStore. It keeps a copy of tx, with
// its timestamps in UTC.
func (s *Store) Save(_ context.Context, tx *oidcclient.Transaction) error {
	if err := tx.Validate(); err != nil {
		return fmt.Errorf("memory: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// A transaction is created now: its creation time is the sweep's clock.
	s.maybeSweep(tx.CreatedAt)

	if _, ok := s.txs[tx.StateHash]; ok {
		return oidcclient.ErrTransactionExists
	}

	if len(s.txs) >= s.capacity {
		s.sweepExpired(tx.CreatedAt)

		if len(s.txs) >= s.capacity {
			return ErrFull
		}
	}

	stored := *tx
	stored.CreatedAt = stored.CreatedAt.UTC()
	stored.ExpiresAt = stored.ExpiresAt.UTC()
	s.txs[tx.StateHash] = stored

	if s.nextExpiry.IsZero() || stored.ExpiresAt.Before(s.nextExpiry) {
		s.nextExpiry = stored.ExpiresAt
	}

	return nil
}

// Consume implements oidcclient.TransactionStore under the store's mutex.
func (s *Store) Consume(_ context.Context, stateHash, bindingHash string, now time.Time) (*oidcclient.Transaction, error) {
	if err := validateKeys(stateHash, bindingHash); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.maybeSweep(now)

	tx, ok := s.txs[stateHash]
	if !ok {
		return nil, oidcclient.ErrTransactionNotFound
	}

	if !now.Before(tx.ExpiresAt) {
		delete(s.txs, stateHash)

		return nil, oidcclient.ErrTransactionNotFound
	}

	if subtle.ConstantTimeCompare([]byte(tx.BindingHash), []byte(bindingHash)) != 1 {
		return nil, oidcclient.ErrBindingMismatch
	}

	delete(s.txs, stateHash)

	return &tx, nil
}

// validateKeys refuses the keys oidcclient.ValidateStoreKey refuses.
func validateKeys(stateHash, bindingHash string) error {
	if err := oidcclient.ValidateStoreKey(stateHash); err != nil {
		return fmt.Errorf("memory: consume: state hash: %w", err)
	}

	if err := oidcclient.ValidateStoreKey(bindingHash); err != nil {
		return fmt.Errorf("memory: consume: binding hash: %w", err)
	}

	return nil
}

// Len returns the number of transactions the store retains, expired ones
// not yet swept included.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.txs)
}

// maybeSweep deletes the expired transactions every sweepEvery operations.
// The caller holds the mutex.
func (s *Store) maybeSweep(now time.Time) {
	s.ops++
	if s.ops%sweepEvery != 0 {
		return
	}

	s.sweepExpired(now)
}

// sweepExpired deletes the expired transactions — walking them only when
// one may have expired at now — and recomputes nextExpiry. The caller holds
// the mutex.
func (s *Store) sweepExpired(now time.Time) {
	if s.nextExpiry.IsZero() || now.Before(s.nextExpiry) {
		return
	}

	s.sweeps++
	s.nextExpiry = time.Time{}

	for hash, tx := range s.txs {
		switch {
		case !now.Before(tx.ExpiresAt):
			delete(s.txs, hash)
		case s.nextExpiry.IsZero() || tx.ExpiresAt.Before(s.nextExpiry):
			s.nextExpiry = tx.ExpiresAt
		}
	}
}
