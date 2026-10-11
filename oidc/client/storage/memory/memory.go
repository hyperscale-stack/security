// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package memory ships an in-process oidcclient.TransactionStore for
// development, tests and single-instance deployments. Its transactions
// live in the process: they are lost on restart and invisible to other
// instances, so a deployment with several instances behind a load balancer
// MUST use a shared store (oidc/client/store/sql or oidc/client/store/redis).
//
// Expired transactions — abandoned logins — are swept every 64 operations,
// so the store stays bounded by the login rate times the transaction TTL.
// One mutex serializes every operation; it is the linearization point of
// the single-consumption guarantee.
package memory

import (
	"context"
	"crypto/subtle"
	"fmt"
	"sync"
	"time"

	oidcclient "github.com/hyperscale-stack/security/oidc/client"
)

// sweepEvery is the number of operations between two sweeps of the
// expired transactions.
const sweepEvery = 64

// Store is an in-memory oidcclient.TransactionStore, safe for concurrent
// use. The zero value is unusable; build one with New.
type Store struct {
	mu  sync.Mutex
	txs map[string]oidcclient.Transaction
	ops int
}

// New returns an empty Store.
func New() *Store {
	return &Store{txs: make(map[string]oidcclient.Transaction)}
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

	stored := *tx
	stored.CreatedAt = stored.CreatedAt.UTC()
	stored.ExpiresAt = stored.ExpiresAt.UTC()
	s.txs[tx.StateHash] = stored

	return nil
}

// Consume implements oidcclient.TransactionStore under the store's mutex.
func (s *Store) Consume(_ context.Context, stateHash, bindingHash string, now time.Time) (*oidcclient.Transaction, error) {
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

	for hash, tx := range s.txs {
		if !now.Before(tx.ExpiresAt) {
			delete(s.txs, hash)
		}
	}
}
