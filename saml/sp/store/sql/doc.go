// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package sqlstore is a database/sql implementation of samlsp.Storage: the
// login transactions of a SAML Service Provider and its assertion replay
// cache, shared by every instance of a deployment. Dialects supported:
// PostgreSQL, MySQL, SQLite. Schema returns the DDL; Store.Migrate applies
// it, and every instance may run it at boot, concurrently.
//
// # Atomicity
//
// Every guarantee rests on one statement:
//
//   - SaveTransaction and MarkAssertionUsed are plain INSERTs on a primary
//     key: of concurrent inserts of one key, the database lets exactly one
//     commit. A failed insert is classified by reading whether the key now
//     exists (ErrTransactionExists / ErrAssertionReplayed) — never from
//     RowsAffected, so a MySQL connection with CLIENT_FOUND_ROWS cannot turn
//     a replay into a success.
//   - ConsumeTransaction is one UPDATE … SET consumed = 1 WHERE id = ? AND
//     consumed = 0 AND binding_hash = ?. A concurrent UPDATE of the row
//     waits for the row lock, then re-evaluates the predicate on the
//     committed row (PostgreSQL READ COMMITTED, MySQL InnoDB locking reads,
//     SQLite's single writer): exactly one caller sees one affected row. A
//     row only moves from unconsumed to consumed, so the follow-up read that
//     classifies a failure (not found, consumed, binding mismatch) cannot be
//     raced into a wrong answer.
//
// # Deployment requirements
//
//   - Every instance uses the same database, reaching the primary: a read
//     replica could report a consumed transaction or a recorded assertion as
//     absent.
//   - MySQL tables must use InnoDB.
//   - SQLite: one writer at a time; set a busy timeout (with
//     modernc.org/sqlite, the _pragma=busy_timeout(5000) DSN option).
//   - Every column holds ASCII (hex digests, ASCII-only JSON, integers): no
//     character set, collation or sql_mode requirement. The keys are 64
//     lowercase hex digits, validated at every call: no collation takes one
//     key for another.
//   - Give the SP a database user limited to the two tables: each record
//     carries a MAC under samlsp.Config.TransactionKeys, so the database is
//     trusted for availability and single consumption only.
//
// # Upgrading
//
// Migrate never alters an existing table. A samlsp_transactions table
// created before the integrity column needs it before the new version
// runs:
//
//	ALTER TABLE samlsp_transactions ADD COLUMN integrity VARCHAR(64) NOT NULL DEFAULT ''
//
// or can be dropped and recreated with Migrate: it only holds logins in
// progress, which fail once either way.
//
// The CI of this module exercises SQLite only; the PostgreSQL and MySQL
// guarantees are argued from the statements above, and checked by the
// opt-in suites of internal/interop/saml and internal/interop/sqlstores on
// real servers.
//
// # Cleanup
//
// The store ships no expiry job. Both tables carry expires_at (Unix
// seconds): delete the rows past it, in small batches by primary key, from
// a scheduled job:
//
//	DELETE FROM samlsp_transactions    WHERE expires_at < ?
//	DELETE FROM samlsp_used_assertions WHERE expires_at < ?
//
// A row deleted after its expiry changes nothing: an expired transaction is
// refused anyway, and an assertion is never accepted after its replay
// entry's expiry. The DDL creates no index (MySQL has no CREATE INDEX IF NOT
// EXISTS): add one on expires_at through your migration tool. BeginLogin
// inserts a row per unauthenticated login attempt, so rate-limit it.
//
// Allowed dependencies:
//   - github.com/hyperscale-stack/security/saml/sp
//   - database/sql
//   - stdlib only (drivers are pluggable; users bring their own)
package sqlstore
