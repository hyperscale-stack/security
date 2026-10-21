// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package sqlstore is a database/sql implementation of
// oidcclient.TransactionStore, the store of pending OpenID Connect logins,
// for deployments whose instances share a database. Dialects supported:
// PostgreSQL, MySQL, SQLite. Schema returns the DDL; Store.Migrate applies
// it, and every instance may run it at boot, concurrently.
//
// The table holds no secret: transactions are keyed by a hash of the
// state, the browser binding is a keyed hash, and the nonce and PKCE
// verifier are derived from the binding secret only the user agent holds.
// Reading the table yields nothing that completes a login. A row altered in
// the table fails its login (oidcclient.ErrTransactionIntegrity): its
// integrity MAC is keyed by the binding secret and a transaction key the
// database never sees (oidcclient.Config.TransactionKeys), so write access
// to the table cannot relax a login's max_age or acr_values checks. The
// database is trusted for availability and single consumption.
//
// # Deployment requirements
//
// The single-consumption guarantee holds under these conditions:
//
//   - PostgreSQL: Consume runs at READ COMMITTED whatever the server
//     default (see [Postgres]).
//   - MySQL: the table must use InnoDB (row locks); utf8mb4 is not
//     required — every column holds ASCII. Nor is a binary collation: the
//     keys are 64 lowercase hex digits — validated by Save and by Consume
//     (oidcclient.ValidateStoreKey), and the binding hash is compared in
//     Go, in constant time — so no collation takes one key for another.
//   - SQLite: one writer at a time. Set a busy timeout (with
//     modernc.org/sqlite, the _pragma=busy_timeout(5000) DSN option) so a
//     concurrent consumer waits instead of failing with SQLITE_BUSY; a busy
//     error fails the login, closed.
//   - Every instance must reach the primary database: a replica, or a
//     read/write-splitting proxy, could answer from before a consumption.
//
// The tests of this module run on SQLite, with several connections racing
// on a database file. The PostgreSQL and MySQL guarantees rest on the
// locking described in [Store], which the suites of
// internal/interop/oidcstack and internal/interop/sqlstores check in CI
// (make test-backends) on PostgreSQL, MySQL and MariaDB servers.
//
// # Cleanup
//
// Consume deletes the transactions it reaches; an abandoned login keeps
// its row until [Store.PurgeExpired] deletes it, so schedule that call.
// The DDL creates no index — MySQL has no CREATE INDEX IF NOT EXISTS — so
// add one on expires_at through your migration tool: without it, the purge
// scans the table and, on MySQL, locks every row it scans, holding back the
// logins starting or completing meanwhile. A transaction lives minutes,
// so the table stays small when the purge runs every few minutes; the
// purge is one DELETE, not batched.
//
// Allowed dependencies:
//   - github.com/hyperscale-stack/security/oidc/client
//   - database/sql
//   - stdlib only (drivers are pluggable; users bring their own)
package sqlstore
