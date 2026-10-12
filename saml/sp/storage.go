// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// MaxTransactionPayloadSize bounds [TransactionRecord.Payload].
const MaxTransactionPayloadSize = 16 << 10

// storeKeyLen is the length of every store key: a lowercase hex SHA-256.
const storeKeyLen = 64

// TransactionRecord is what a [TransactionStore] persists for one
// SP-initiated login. The store treats Payload as opaque: only the
// [ServiceProvider] encodes and decodes it. No secret is stored: ID and
// BindingHash are SHA-256 digests of the RelayState handle and of the
// browser-binding cookie, which never reach the store.
type TransactionRecord struct {
	// ID is the store key: 64 lowercase hex characters.
	ID string
	// BindingHash is the digest the consuming browser must match: 64
	// lowercase hex characters.
	BindingHash string
	// Payload is the SP-encoded transaction state (valid UTF-8, no NUL,
	// at most MaxTransactionPayloadSize bytes).
	Payload string
	// ExpiresAt is the expiry, in whole seconds. Stores MUST return it
	// unchanged.
	ExpiresAt time.Time
}

// Validate checks the record before any store I/O; it returns an error
// matching [ErrInvalidStoreRecord].
func (r *TransactionRecord) Validate() error {
	if r == nil {
		return fmt.Errorf("%w: nil transaction record", ErrInvalidStoreRecord)
	}

	if err := ValidateStoreKey(r.ID); err != nil {
		return fmt.Errorf("transaction ID: %w", err)
	}

	if err := ValidateStoreKey(r.BindingHash); err != nil {
		return fmt.Errorf("binding hash: %w", err)
	}

	switch {
	case r.Payload == "":
		return fmt.Errorf("%w: empty payload", ErrInvalidStoreRecord)
	case len(r.Payload) > MaxTransactionPayloadSize:
		return fmt.Errorf("%w: payload over %d bytes", ErrInvalidStoreRecord, MaxTransactionPayloadSize)
	case !utf8.ValidString(r.Payload) || strings.IndexByte(r.Payload, 0) >= 0:
		return fmt.Errorf("%w: payload is not NUL-free UTF-8", ErrInvalidStoreRecord)
	}

	return ValidateExpiry(r.ExpiresAt)
}

// ValidateStoreKey checks that key is 64 lowercase hexadecimal characters,
// the form of every transaction ID, binding hash and replay key; it returns
// an error matching [ErrInvalidStoreRecord].
func ValidateStoreKey(key string) error {
	if len(key) != storeKeyLen {
		return fmt.Errorf("%w: key must be %d hex characters", ErrInvalidStoreRecord, storeKeyLen)
	}

	for i := 0; i < len(key); i++ {
		if c := key[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return fmt.Errorf("%w: key must be lowercase hex", ErrInvalidStoreRecord)
		}
	}

	return nil
}

// ValidateExpiry checks that an expiry is set and has no sub-second part,
// so every store round-trips it exactly; it returns an error matching
// [ErrInvalidStoreRecord].
func ValidateExpiry(t time.Time) error {
	if t.IsZero() || t.Unix() <= 0 {
		return fmt.Errorf("%w: missing expiry", ErrInvalidStoreRecord)
	}

	if t.Nanosecond() != 0 {
		return fmt.Errorf("%w: expiry must be whole seconds", ErrInvalidStoreRecord)
	}

	return nil
}

// TransactionStore persists pending SP-initiated logins. Implementations
// MUST be safe for concurrent use by any number of [ServiceProvider]
// instances sharing the backend, and MUST validate their inputs
// ([TransactionRecord.Validate], [ValidateStoreKey]) before any I/O.
// The conformance suite in package storetest checks this contract.
type TransactionStore interface {
	// SaveTransaction stores a new record. It never overwrites: an existing
	// ID yields ErrTransactionExists.
	SaveTransaction(ctx context.Context, rec *TransactionRecord) error

	// LookupTransaction returns the record without consuming it. It returns
	// ErrTransactionNotFound for an unknown (or purged) ID and
	// ErrTransactionConsumed for a consumed one.
	LookupTransaction(ctx context.Context, id string) (*TransactionRecord, error)

	// ConsumeTransaction marks the record consumed if, and only if, it
	// exists, is not consumed yet and bindingHash equals its BindingHash.
	// Among any number of concurrent callers on any number of instances, at
	// most one gets nil. Others get, in this precedence:
	// ErrTransactionNotFound, ErrTransactionConsumed, then
	// ErrBrowserBindingMismatch — the latter without consuming. A consumed
	// record is retained until its ExpiresAt (a replay is then reported as
	// ErrTransactionConsumed) and MAY be purged afterwards.
	ConsumeTransaction(ctx context.Context, id, bindingHash string) error
}

// ReplayCache records the assertions already consumed (Profiles §4.1.4.5).
// Implementations MUST be safe for concurrent use by any number of
// instances sharing the backend.
type ReplayCache interface {
	// MarkAssertionUsed atomically records key unless present. A present
	// key — expired or not — yields ErrAssertionReplayed, so at most one of
	// any number of concurrent callers gets nil. The key is retained at
	// least until expiresAt (whole seconds) and MAY be purged afterwards.
	MarkAssertionUsed(ctx context.Context, key string, expiresAt time.Time) error
}

// Storage is a backend implementing both stores, as the memory, SQL and
// Redis implementations do. [Config] takes the two roles separately so they
// may live in different backends.
type Storage interface {
	TransactionStore
	ReplayCache
}
