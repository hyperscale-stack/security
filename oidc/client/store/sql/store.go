// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	oidcclient "github.com/hyperscale-stack/security/oidc/client"
)

// The statements of the store, written with "?" placeholders.
const (
	insertTransaction = `INSERT INTO oidc_client_transactions
		(state_hash, binding_hash, connection_id, issuer, client_id, redirect_uri,
		 response_mode, max_age, acr_values, app_state, created_at, expires_at, integrity)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	existsTransaction = `SELECT 1 FROM oidc_client_transactions WHERE state_hash = ?`
	deleteIfExpired   = `DELETE FROM oidc_client_transactions WHERE state_hash = ? AND expires_at <= ?`
	deleteTransaction = `DELETE FROM oidc_client_transactions WHERE state_hash = ?`
	deleteExpired     = `DELETE FROM oidc_client_transactions WHERE expires_at <= ?`
)

// Formats of the errors several statements share.
const (
	errConsumeContext  = "sqlstore: consume transaction: %w"
	errAffectedContext = "sqlstore: rows affected: %w"
)

// Store is a database/sql [oidcclient.TransactionStore], safe for
// concurrent use by every instance sharing the database.
//
// Save is one INSERT; a failed INSERT is told apart from a duplicate state
// hash by reading the key back, whatever the driver's error codes.
//
// Consume runs one transaction that starts with a write — a DELETE of
// the transaction if it has expired, so that expiry is decided before the
// binding and SQLite's write lock is taken before anything is read — then
// reads the row under a row lock (SELECT … FOR UPDATE on PostgreSQL and
// MySQL), compares the binding hash in constant time, and deletes the row:
// the DELETE affecting exactly one row picks the one winner, even on an
// engine without row locks. The transaction is returned only once its
// deletion is committed. A binding mismatch leaves the row in place.
type Store struct {
	db      *sql.DB
	dialect Dialect
}

// New returns a [Store] over db using dialect. The caller owns db's
// lifecycle. Call [Store.Migrate] once at boot, or run the DDL from
// [Schema] through a migration tool.
func New(db *sql.DB, dialect Dialect) (*Store, error) {
	if db == nil {
		return nil, errors.New("sqlstore: New: nil *sql.DB")
	}

	if dialect == nil {
		return nil, errors.New("sqlstore: New: nil Dialect")
	}

	return &Store{db: db, dialect: dialect}, nil
}

// Save implements [oidcclient.TransactionStore].
func (s *Store) Save(ctx context.Context, tx *oidcclient.Transaction) error {
	if err := tx.Validate(); err != nil {
		return fmt.Errorf("sqlstore: %w", err)
	}

	_, err := s.db.ExecContext(ctx, s.dialect.rebind(insertTransaction),
		tx.StateHash, tx.BindingHash, tx.ConnectionID, tx.Issuer, tx.ClientID, tx.RedirectURI,
		string(tx.ResponseMode), tx.MaxAge, tx.ACRValues, base64.StdEncoding.EncodeToString([]byte(tx.AppState)),
		tx.CreatedAt.Unix(), tx.ExpiresAt.Unix(), tx.Integrity)
	if err == nil {
		return nil
	}

	// The key is there: the INSERT met a duplicate, the stored row is
	// untouched. A failure of this read reports the INSERT's error.
	var one int
	if s.db.QueryRowContext(ctx, s.dialect.rebind(existsTransaction), tx.StateHash).Scan(&one) == nil {
		return oidcclient.ErrTransactionExists
	}

	return fmt.Errorf("sqlstore: save transaction: %w", err)
}

// Consume implements [oidcclient.TransactionStore] (see [Store]). It
// refuses, before any I/O, keys [oidcclient.ValidateStoreKey] refuses: a
// MySQL VARCHAR key compares under a case-insensitive, space-padding
// collation, which would otherwise take a malformed key for a stored one.
func (s *Store) Consume(ctx context.Context, stateHash, bindingHash string, now time.Time) (*oidcclient.Transaction, error) {
	if err := validateKeys(stateHash, bindingHash); err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTx(ctx, s.dialect.txOptions())
	if err != nil {
		return nil, fmt.Errorf("sqlstore: begin: %w", err)
	}

	defer func() { _ = tx.Rollback() }() // a no-op once committed

	record, err := s.take(ctx, tx, stateHash, bindingHash, now)
	if err != nil && !errors.Is(err, oidcclient.ErrTransactionNotFound) && !errors.Is(err, oidcclient.ErrBindingMismatch) {
		return nil, err
	}

	// Committed on a verdict too: it keeps the purge of an expired
	// transaction.
	if cerr := tx.Commit(); cerr != nil {
		return nil, fmt.Errorf("sqlstore: commit: %w", cerr)
	}

	return record, err
}

// validateKeys refuses the keys oidcclient.ValidateStoreKey refuses.
func validateKeys(stateHash, bindingHash string) error {
	if err := oidcclient.ValidateStoreKey(stateHash); err != nil {
		return fmt.Errorf("sqlstore: consume transaction: state hash: %w", err)
	}

	if err := oidcclient.ValidateStoreKey(bindingHash); err != nil {
		return fmt.Errorf("sqlstore: consume transaction: binding hash: %w", err)
	}

	return nil
}

// take decides Consume within tx, in the order the contract pins.
func (s *Store) take(ctx context.Context, tx *sql.Tx, stateHash, bindingHash string, now time.Time) (*oidcclient.Transaction, error) {
	if _, err := tx.ExecContext(ctx, s.dialect.rebind(deleteIfExpired), stateHash, now.Unix()); err != nil {
		return nil, fmt.Errorf(errConsumeContext, err)
	}

	record, err := s.lockRow(ctx, tx, stateHash)
	if err != nil {
		return nil, err
	}

	if subtle.ConstantTimeCompare([]byte(record.BindingHash), []byte(bindingHash)) != 1 {
		return nil, oidcclient.ErrBindingMismatch
	}

	res, err := tx.ExecContext(ctx, s.dialect.rebind(deleteTransaction), stateHash)
	if err != nil {
		return nil, fmt.Errorf(errConsumeContext, err)
	}

	n, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf(errAffectedContext, err)
	}

	if n != 1 {
		return nil, oidcclient.ErrTransactionNotFound // deleted by a concurrent consumer
	}

	return record, nil
}

// lockRow reads the transaction stateHash within tx under a row lock.
func (s *Store) lockRow(ctx context.Context, tx *sql.Tx, stateHash string) (*oidcclient.Transaction, error) {
	var (
		t                  oidcclient.Transaction
		mode, appState     string
		createdAt, expires int64
	)

	err := tx.QueryRowContext(ctx, s.dialect.rebind(s.dialect.lockRow()), stateHash).Scan(
		&t.StateHash, &t.BindingHash, &t.ConnectionID, &t.Issuer, &t.ClientID, &t.RedirectURI,
		&mode, &t.MaxAge, &t.ACRValues, &appState, &createdAt, &expires, &t.Integrity)

	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, oidcclient.ErrTransactionNotFound
	case err != nil:
		return nil, fmt.Errorf("sqlstore: read transaction: %w", err)
	}

	state, err := base64.StdEncoding.DecodeString(appState)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: read transaction: app state: %w", err)
	}

	t.ResponseMode = oidcclient.ResponseMode(mode)
	t.AppState = string(state)
	t.CreatedAt = time.Unix(createdAt, 0).UTC()
	t.ExpiresAt = time.Unix(expires, 0).UTC()

	return &t, nil
}

// PurgeExpired deletes the transactions expired at now — abandoned logins,
// which Consume never reaches — and returns how many it deleted. Schedule
// it, every few minutes for instance: nothing else deletes them. It is one
// DELETE statement (see the package documentation for its index), in a
// transaction at READ COMMITTED on PostgreSQL and MySQL. On MySQL, READ
// COMMITTED keeps it from locking the gaps it scans, which would block the
// logins starting meanwhile; a server logging statements
// (binlog_format=STATEMENT) refuses it, and the purge fails, closed.
func (s *Store) PurgeExpired(ctx context.Context, now time.Time) (int64, error) {
	tx, err := s.db.BeginTx(ctx, s.dialect.purgeTxOptions())
	if err != nil {
		return 0, fmt.Errorf("sqlstore: purge expired transactions: begin: %w", err)
	}

	defer func() { _ = tx.Rollback() }() // a no-op once committed

	res, err := tx.ExecContext(ctx, s.dialect.rebind(deleteExpired), now.Unix())
	if err != nil {
		return 0, fmt.Errorf("sqlstore: purge expired transactions: %w", err)
	}

	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf(errAffectedContext, err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("sqlstore: purge expired transactions: commit: %w", err)
	}

	return n, nil
}
