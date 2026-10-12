// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package memory ships an in-process [samlsp.Storage] for development and
// tests. Production deployments with more than one instance MUST use the
// SQL or Redis stores: this one keeps its state in the process, loses it on
// restart, and never purges anything — every transaction and every consumed
// assertion stays in memory for the process lifetime.
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

// Store is an in-memory [samlsp.Storage]. Build one with [New].
type Store struct {
	mu   sync.Mutex
	txs  map[string]entry
	used map[string]time.Time
}

// entry is a stored transaction and its consumption flag.
type entry struct {
	rec      samlsp.TransactionRecord
	consumed bool
}

// New returns an empty [Store].
func New() *Store {
	return &Store{
		txs:  make(map[string]entry),
		used: make(map[string]time.Time),
	}
}

// SaveTransaction implements [samlsp.TransactionStore]: it stores a copy
// of rec unless its ID exists.
func (s *Store) SaveTransaction(_ context.Context, rec *samlsp.TransactionRecord) error {
	if err := rec.Validate(); err != nil {
		return fmt.Errorf("memory: save transaction: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.txs[rec.ID]; ok {
		return samlsp.ErrTransactionExists
	}

	s.txs[rec.ID] = entry{rec: *rec}

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

	if _, ok := s.used[key]; ok {
		return samlsp.ErrAssertionReplayed
	}

	s.used[key] = expiresAt

	return nil
}
