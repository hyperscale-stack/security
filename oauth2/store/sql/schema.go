// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore

import (
	"context"
	"fmt"
)

// Schema returns the DDL statements that create the four tables backing
// the store: authorization codes — a consumed one keeps its row, flagged
// consumed, until an operator deletes it — access tokens, refresh tokens,
// and the token families — one record per family, active (revoked_at = 0)
// or revoked (revoked_at = Unix second of the first revocation), retained
// until expires_at. Timestamps are stored as BIGINT Unix seconds to dodge the
// TIMESTAMP / DATETIME portability minefield between engines, and flags as
// SMALLINT 0/1 since PostgreSQL has no implicit integer/boolean cast. Token
// / code raw values are NEVER stored — only their hashes.
//
// The DDL sticks to the subset every supported engine accepts, and is the
// same for every [Dialect] but for the type of the key columns — the code
// and token hashes and the token-family IDs, the only columns the
// statements compare: VARCHAR on PostgreSQL and SQLite, which compare it
// byte for byte, VARBINARY on MySQL, whose text comparisons follow a
// collation that may ignore case, accents or trailing spaces — and for the
// table options of MySQL: ENGINE=InnoDB DEFAULT CHARSET=utf8mb4, since a
// server whose default engine is MyISAM would otherwise create tables
// without transactions or row locks, losing the atomic writes (I3) of
// [oauth2.Storage]. A nil Dialect gets the PostgreSQL / SQLite DDL. A MySQL
// database created before the key columns were binary, or with MyISAM
// tables, is upgraded with the statements MIGRATION.md lists.
//
// The issuer and extension_data columns of codes and tokens — the realm a
// grant is bound to and the opaque state an oauth2.Extension recorded for
// it — are nullable TEXT, the only form every engine accepts
// in an ALTER TABLE … ADD COLUMN on a populated table, so a database
// created before them is upgraded with the statements MIGRATION.md lists
// and ends up with the same columns as a new one. The store writes an
// empty value as the empty string and reads NULL as the empty string. The
// redirect_uri_omitted flag of codes is a SMALLINT NOT NULL DEFAULT 0, and
// the family_issued_at of refresh tokens a BIGINT NOT NULL DEFAULT 0 (0: no
// recorded family start), which every engine also accepts on a populated
// table: a row written before them reads 0.
//
// The statements are idempotent (CREATE TABLE IF NOT EXISTS), and each is
// valid inside a PostgreSQL transaction block, where [Store.Migrate] runs
// them. Production deployments typically run them through a migration tool
// rather than via Migrate, but Migrate is offered for tests and small
// setups.
func Schema(d Dialect) []string {
	if d == nil {
		d = sqlite{}
	}

	// 64: oauth2.MaxFamilyIDLength, in bytes.
	hash, family, options := d.keyType(128), d.keyType(64), d.tableOptions()

	return []string{
		`CREATE TABLE IF NOT EXISTS oauth2_auth_codes (
			code_hash             ` + hash + ` PRIMARY KEY,
			client_id             VARCHAR(255) NOT NULL,
			subject               VARCHAR(255) NOT NULL,
			redirect_uri          TEXT         NOT NULL,
			scope                 TEXT         NOT NULL,
			code_challenge        TEXT         NOT NULL,
			code_challenge_method VARCHAR(16)  NOT NULL,
			nonce                 TEXT         NOT NULL,
			consumed              SMALLINT     NOT NULL DEFAULT 0,
			issued_at             BIGINT       NOT NULL,
			expires_at            BIGINT       NOT NULL,
			issuer                TEXT,
			extension_data        TEXT,
			redirect_uri_omitted  SMALLINT     NOT NULL DEFAULT 0
		)` + options,
		`CREATE TABLE IF NOT EXISTS oauth2_access_tokens (
			token_hash ` + hash + ` PRIMARY KEY,
			client_id  VARCHAR(255) NOT NULL,
			subject    VARCHAR(255) NOT NULL,
			scope      TEXT         NOT NULL,
			family_id  ` + family + `  NOT NULL,
			audience   VARCHAR(255) NOT NULL,
			issued_at  BIGINT       NOT NULL,
			expires_at BIGINT       NOT NULL,
			issuer         TEXT,
			extension_data TEXT
		)` + options,
		`CREATE TABLE IF NOT EXISTS oauth2_refresh_tokens (
			token_hash ` + hash + ` PRIMARY KEY,
			client_id  VARCHAR(255) NOT NULL,
			subject    VARCHAR(255) NOT NULL,
			scope      TEXT         NOT NULL,
			family_id  ` + family + `  NOT NULL,
			consumed   SMALLINT     NOT NULL DEFAULT 0,
			issued_at  BIGINT       NOT NULL,
			expires_at BIGINT       NOT NULL,
			issuer         TEXT,
			extension_data TEXT,
			family_issued_at BIGINT NOT NULL DEFAULT 0
		)` + options,
		`CREATE TABLE IF NOT EXISTS oauth2_token_families (
			family_id  ` + family + `  PRIMARY KEY,
			revoked_at BIGINT       NOT NULL DEFAULT 0,
			expires_at BIGINT       NOT NULL
		)` + options,
	}
}

// Migrate applies [Schema] to the store's database: it creates the missing
// tables and never alters an existing one — the columns a release adds to
// an existing table are added with the statements MIGRATION.md lists,
// through your migration tool, before the release serves traffic. It then
// runs [Store.CheckDeployment], and fails with its error: a table that
// exists already keeps its engine and its column types, so a deployment
// that does not meet the requirements is refused at boot.
//
// It is safe to call repeatedly, and concurrently — every instance of a
// deployment starting at once. On PostgreSQL, where concurrent CREATE
// TABLE IF NOT EXISTS of one table can fail, Migrate runs in one
// transaction that first takes the transaction-level advisory lock
// -2450120788798466590 (pg_advisory_xact_lock; see [Postgres]): concurrent
// calls run one after the other, and a failed call creates nothing. A
// waiting call waits as long as ctx — and the server's lock_timeout or
// statement_timeout — allows: pass a deadline; the driver cancels the
// server-side wait when ctx ends. A migration tool applying [Schema]
// concurrently with Migrate should take the same lock. An engine without
// pg_advisory_xact_lock cannot use Migrate: apply Schema with your own
// tool. On MySQL and MariaDB, where concurrent CREATE TABLE IF NOT EXISTS
// of one table can fail with a metadata-lock deadlock, Migrate creates the
// tables and runs the check on one connection holding the named lock
// "hyperscale-stack/security/oauth2/store/sql.Migrate" (GET_LOCK; named
// locks are server-wide), which it releases before returning: concurrent
// calls run one after the other, waiting as long as ctx allows. SQLite
// serializes the creation of a table on its write lock — given the busy
// timeout the package documentation requires, without which a concurrent
// call fails with SQLITE_BUSY: there each statement runs on its own.
func (s *Store) Migrate(ctx context.Context) error {
	if name := s.dialect.namedMigrationLock(); name != "" {
		return s.migrateUnderNamedLock(ctx, name)
	}

	if err := s.createTables(ctx); err != nil {
		return err
	}

	return s.CheckDeployment(ctx)
}

// createTables applies [Schema]: under the dialect's migration lock when it
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

// migrateLocked applies [Schema] in one transaction that first runs lock,
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
