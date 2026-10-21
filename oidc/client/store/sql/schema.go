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
// the same for every [Dialect] but for the table options of MySQL:
// ENGINE=InnoDB DEFAULT CHARSET=utf8mb4, since a server whose default
// engine is MyISAM would otherwise create a table without row locks or
// crash safety. A nil Dialect gets the PostgreSQL / SQLite DDL. It creates
// no index — MySQL has no CREATE INDEX IF NOT EXISTS — see the package
// documentation for the one on expires_at.
//
// The statement is idempotent (CREATE TABLE IF NOT EXISTS) and valid
// inside a PostgreSQL transaction block, where [Store.Migrate] runs it.
// Production deployments typically run it through a migration tool rather
// than via Migrate.
func Schema(d Dialect) []string {
	if d == nil {
		d = sqlite{}
	}

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
		)` + d.tableOptions(),
	}
}

// Migrate applies [Schema] to the store's database: it creates the table
// when missing and never alters it. It then runs [Store.CheckDeployment],
// and fails with its error: a table that exists already keeps its engine,
// so a deployment that does not meet the requirements is refused at boot.
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
// tool. On MySQL and MariaDB, where concurrent CREATE TABLE IF NOT EXISTS
// of one table can fail with a metadata-lock deadlock, Migrate creates the
// tables and runs the check on one connection holding the named lock
// "hyperscale-stack/security/oidc/client/store/sql.Migrate" (GET_LOCK; named
// locks are server-wide), which it releases before returning: concurrent
// calls run one after the other, waiting as long as ctx allows. A holder
// whose client vanished keeps the lock until the server notices
// (wait_timeout): find it with SELECT IS_USED_LOCK('<name>') and KILL it.
// On a Galera or Percona XtraDB cluster named locks are local to a node, so
// Migrate calls through different nodes are not serialized. SQLite
// serializes the creation of a table on its write lock — given the busy
// timeout the package documentation requires, without which a concurrent
// call fails with SQLITE_BUSY.
func (s *Store) Migrate(ctx context.Context) error {
	if name := s.dialect.namedMigrationLock(); name != "" {
		return s.migrateUnderNamedLock(ctx, name)
	}

	if err := s.createTable(ctx); err != nil {
		return err
	}

	return s.CheckDeployment(ctx)
}

// createTable applies [Schema]: under the dialect's migration lock when it
// has one, on its own otherwise.
func (s *Store) createTable(ctx context.Context) error {
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
