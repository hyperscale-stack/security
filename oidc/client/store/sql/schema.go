// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore

import (
	"context"
	"fmt"
)

// Schema returns the DDL of the table backing the store,
// oidc_client_transactions: one row per pending login, keyed by the state
// hash. Timestamps are BIGINT Unix seconds, which every engine stores
// alike; app_state holds the application state base64-encoded, so that any
// UTF-8 — NUL included, which PostgreSQL text refuses — round-trips whatever
// the column character set; integrity holds the transaction's MAC. No column
// holds a secret (see oidcclient.Transaction).
//
// The DDL sticks to the subset every supported engine accepts, so it is
// the same for every [Dialect]: the argument is accepted for API stability
// and ignored. It creates no index — MySQL has no CREATE INDEX IF NOT
// EXISTS — see the package documentation for the one on expires_at.
//
// The statement is idempotent (CREATE TABLE IF NOT EXISTS) and valid
// inside a PostgreSQL transaction block, where [Store.Migrate] runs it.
// Production deployments typically run it through a migration tool rather
// than via Migrate.
func Schema(_ Dialect) []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS oidc_client_transactions (
			state_hash    VARCHAR(64)  PRIMARY KEY,
			binding_hash  VARCHAR(64)  NOT NULL,
			connection_id VARCHAR(255) NOT NULL,
			issuer        TEXT         NOT NULL,
			client_id     TEXT         NOT NULL,
			redirect_uri  TEXT         NOT NULL,
			response_mode VARCHAR(16)  NOT NULL,
			max_age       BIGINT       NOT NULL,
			acr_values    TEXT         NOT NULL,
			app_state     TEXT         NOT NULL,
			created_at    BIGINT       NOT NULL,
			expires_at    BIGINT       NOT NULL,
			integrity     VARCHAR(64)  NOT NULL
		)`,
	}
}

// Migrate applies [Schema] to the store's database: it creates the table
// when missing and never alters it.
//
// It is safe to call repeatedly, and concurrently — every instance of a
// deployment starting at once. On PostgreSQL, where concurrent CREATE
// TABLE IF NOT EXISTS of one table can fail, Migrate runs in one
// transaction that first takes the transaction-level advisory lock
// -3346565968272468758 (pg_advisory_xact_lock; see [Postgres]): concurrent
// calls run one after the other, and a failed call creates nothing. A
// waiting call waits as long as ctx — and the server's lock_timeout or
// statement_timeout — allows: pass a deadline; the driver cancels the
// server-side wait when ctx ends. A migration tool applying [Schema]
// concurrently with Migrate should take the same lock. An engine without
// pg_advisory_xact_lock cannot use Migrate: apply Schema with your own
// tool. MySQL serializes the creation of a table on the metadata lock of
// its name, and SQLite on its write lock — given the busy timeout the
// package documentation requires, without which a concurrent call fails
// with SQLITE_BUSY.
func (s *Store) Migrate(ctx context.Context) error {
	if lock := s.dialect.migrationLock(); lock != "" {
		return s.migrateLocked(ctx, lock)
	}

	for _, stmt := range Schema(s.dialect) {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("sqlstore: migrate: %w", err)
		}
	}

	return nil
}

// migrateLocked applies [Schema] in one transaction that first runs lock,
// the dialect's migration lock: the transaction holds the lock until it
// commits the table, or rolls everything back.
func (s *Store) migrateLocked(ctx context.Context, lock string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlstore: migrate: begin: %w", err)
	}

	defer func() { _ = tx.Rollback() }() // a no-op once committed

	for _, stmt := range append([]string{lock}, Schema(s.dialect)...) {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("sqlstore: migrate: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlstore: migrate: commit: %w", err)
	}

	return nil
}
