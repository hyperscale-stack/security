// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	samlsp "github.com/hyperscale-stack/security/saml/sp"
)

// Store is a database/sql-backed samlsp.Storage (see the package
// documentation for its atomicity and deployment requirements).
type Store struct {
	db      *sql.DB
	dialect Dialect
}

// New returns a Store bound to db. The caller owns db's lifecycle and runs
// Migrate (or applies Schema) once.
func New(db *sql.DB, dialect Dialect) (*Store, error) {
	if db == nil {
		return nil, errors.New("sqlstore: New: nil *sql.DB")
	}

	if dialect == nil {
		return nil, errors.New("sqlstore: New: nil Dialect")
	}

	return &Store{db: db, dialect: dialect}, nil
}

func (s *Store) exec(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return s.db.ExecContext(ctx, s.dialect.rebind(q), args...) //nolint:wrapcheck // wrapped by callers
}

func (s *Store) queryRow(ctx context.Context, q string, args ...any) *sql.Row {
	return s.db.QueryRowContext(ctx, s.dialect.rebind(q), args...)
}

// SaveTransaction implements samlsp.TransactionStore with a plain INSERT.
func (s *Store) SaveTransaction(ctx context.Context, rec *samlsp.TransactionRecord) error {
	if err := rec.Validate(); err != nil {
		return fmt.Errorf("sqlstore: save transaction: %w", err)
	}

	_, err := s.exec(ctx, `INSERT INTO samlsp_transactions (id, binding_hash, payload, consumed, expires_at, integrity)
		VALUES (?, ?, ?, 0, ?, ?)`, rec.ID, rec.BindingHash, rec.Payload, rec.ExpiresAt.Unix(), rec.Integrity)
	if err == nil {
		return nil
	}

	return s.classifyInsert(ctx, err, `SELECT 1 FROM samlsp_transactions WHERE id = ?`, rec.ID, samlsp.ErrTransactionExists)
}

// classifyInsert turns a failed INSERT into conflict when the key exists,
// and returns the original error otherwise.
func (s *Store) classifyInsert(ctx context.Context, insertErr error, existsQuery, key string, conflict error) error {
	var one int

	err := s.queryRow(ctx, existsQuery, key).Scan(&one)

	switch {
	case err == nil:
		return conflict
	case errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("sqlstore: insert: %w", insertErr)
	default:
		return fmt.Errorf("sqlstore: insert: %w", errors.Join(insertErr, err))
	}
}

// LookupTransaction implements samlsp.TransactionStore.
func (s *Store) LookupTransaction(ctx context.Context, id string) (*samlsp.TransactionRecord, error) {
	if err := samlsp.ValidateStoreKey(id); err != nil {
		return nil, fmt.Errorf("sqlstore: lookup transaction: %w", err)
	}

	var (
		rec      = &samlsp.TransactionRecord{ID: id}
		consumed int
		expires  int64
	)

	err := s.queryRow(ctx, `SELECT binding_hash, payload, consumed, expires_at, integrity FROM samlsp_transactions WHERE id = ?`, id).
		Scan(&rec.BindingHash, &rec.Payload, &consumed, &expires, &rec.Integrity)

	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, samlsp.ErrTransactionNotFound
	case err != nil:
		return nil, fmt.Errorf("sqlstore: lookup transaction: %w", err)
	case consumed != 0:
		return nil, samlsp.ErrTransactionConsumed
	}

	rec.ExpiresAt = time.Unix(expires, 0)

	return rec, nil
}

// ConsumeTransaction implements samlsp.TransactionStore with one guarded
// UPDATE; a failure is classified by reading the row.
func (s *Store) ConsumeTransaction(ctx context.Context, id, bindingHash string) error {
	if err := samlsp.ValidateStoreKey(id); err != nil {
		return fmt.Errorf("sqlstore: consume transaction: %w", err)
	}

	if err := samlsp.ValidateStoreKey(bindingHash); err != nil {
		return fmt.Errorf("sqlstore: consume transaction: %w", err)
	}

	res, err := s.exec(ctx, `UPDATE samlsp_transactions SET consumed = 1
		WHERE id = ? AND consumed = 0 AND binding_hash = ?`, id, bindingHash)
	if err != nil {
		return fmt.Errorf("sqlstore: consume transaction: %w", err)
	}

	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlstore: consume transaction: %w", err)
	}

	if n == 1 {
		return nil
	}

	var consumed int

	err = s.queryRow(ctx, `SELECT consumed FROM samlsp_transactions WHERE id = ?`, id).Scan(&consumed)

	switch {
	case errors.Is(err, sql.ErrNoRows):
		return samlsp.ErrTransactionNotFound
	case err != nil:
		return fmt.Errorf("sqlstore: consume transaction: %w", err)
	case consumed != 0:
		return samlsp.ErrTransactionConsumed
	default:
		return samlsp.ErrBrowserBindingMismatch
	}
}

// MarkAssertionUsed implements samlsp.ReplayCache with a plain INSERT.
func (s *Store) MarkAssertionUsed(ctx context.Context, key string, expiresAt time.Time) error {
	if err := samlsp.ValidateStoreKey(key); err != nil {
		return fmt.Errorf("sqlstore: mark assertion: %w", err)
	}

	if err := samlsp.ValidateExpiry(expiresAt); err != nil {
		return fmt.Errorf("sqlstore: mark assertion: %w", err)
	}

	_, err := s.exec(ctx, `INSERT INTO samlsp_used_assertions (assertion_key, expires_at) VALUES (?, ?)`,
		key, expiresAt.Unix())
	if err == nil {
		return nil
	}

	return s.classifyInsert(ctx, err, `SELECT 1 FROM samlsp_used_assertions WHERE assertion_key = ?`, key,
		samlsp.ErrAssertionReplayed)
}
