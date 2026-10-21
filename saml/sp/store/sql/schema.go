// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore

import (
	"context"
	"fmt"
)

// Schema returns the DDL of the two tables backing the store:
//
//   - samlsp_transactions: one row per login transaction, keyed by the
//     digest of (connection, RelayState handle); binding_hash is the digest
//     of the browser-binding cookie; payload is opaque SP state (ASCII);
//     consumed is 0 or 1; expires_at is in Unix seconds; integrity is the
//     record's MAC under a server-held key (samlsp.Config.TransactionKeys).
//   - samlsp_used_assertions: one row per consumed assertion, keyed by the
//     digest of (connection, issuer, assertion ID), kept at least until
//     expires_at.
//
// No secret is stored: keys and binding values are SHA-256 digests, and
// the MAC's key never reaches the database. Every column holds ASCII. The DDL
// is the same for every Dialect (portable types, no BOOLEAN, no index) but
// for the table options of MySQL: ENGINE=InnoDB DEFAULT CHARSET=utf8mb4,
// since a server whose default engine is MyISAM would otherwise create
// tables without crash safety. A nil Dialect gets the PostgreSQL / SQLite
// DDL. The statements are idempotent (CREATE TABLE IF NOT EXISTS) and valid
// inside a PostgreSQL transaction block, where Migrate runs them.
func Schema(d Dialect) []string {
	if d == nil {
		d = sqlite{}
	}

	options := d.tableOptions()

	return []string{
		`CREATE TABLE IF NOT EXISTS samlsp_transactions (
			id           VARCHAR(64) PRIMARY KEY,
			binding_hash VARCHAR(64) NOT NULL,
			payload      TEXT        NOT NULL,
			consumed     SMALLINT    NOT NULL DEFAULT 0,
			expires_at   BIGINT      NOT NULL,
			integrity    VARCHAR(64) NOT NULL
		)` + options,
		`CREATE TABLE IF NOT EXISTS samlsp_used_assertions (
			assertion_key VARCHAR(64) PRIMARY KEY,
			expires_at    BIGINT      NOT NULL
		)` + options,
	}
}

// Migrate applies Schema: it creates the missing tables and never alters
// an existing one. It then runs CheckDeployment, and fails with its error:
// a table that exists already keeps its engine, so a deployment that does
// not meet the requirements is refused at boot.
//
// It is safe to call repeatedly, and concurrently — every instance of a
// deployment starting at once. On PostgreSQL, where concurrent CREATE
// TABLE IF NOT EXISTS of one table can fail, Migrate runs in one
// transaction that first takes the transaction-level advisory lock
// 1266919442082856213 (pg_advisory_xact_lock; see Postgres): concurrent
// calls run one after the other, and a failed call creates nothing. A
// waiting call waits as long as ctx — and the server's lock_timeout or
// statement_timeout — allows: pass a deadline; the driver cancels the
// server-side wait when ctx ends. A migration tool applying Schema
// concurrently with Migrate should take the same lock. An engine without
// pg_advisory_xact_lock cannot use Migrate: apply Schema with your own
// tool. MySQL serializes the creation of a table on the metadata lock of
// its name, and SQLite on its write lock — given the busy timeout the
// package documentation requires, without which a concurrent call fails
// with SQLITE_BUSY: there each statement runs on its own.
func (s *Store) Migrate(ctx context.Context) error {
	if err := s.createTables(ctx); err != nil {
		return err
	}

	return s.CheckDeployment(ctx)
}

// createTables applies Schema: under the dialect's migration lock when it
// has one, statement by statement otherwise.
func (s *Store) createTables(ctx context.Context) error {
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

// migrateLocked applies Schema in one transaction that first runs lock,
// the dialect's migration lock: the transaction holds the lock until it
// commits the tables, or rolls everything back.
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
