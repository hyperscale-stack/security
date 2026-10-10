// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package sqlstore is a database/sql implementation of oauth2.Storage with
// real atomicity: a transactional ConsumeAuthorizationCode, and one record
// per token family (oauth2_token_families) that every issuance, rotation,
// revocation and lookup goes through. Dialects supported: PostgreSQL,
// MySQL, SQLite. Schema returns the DDL; Store.Migrate applies it.
//
// # Deployment requirements
//
// The token-family guarantees of oauth2.Storage hold under these
// conditions; outside them a revocation can be lost or hidden.
//
//   - PostgreSQL: the store runs every transaction at READ COMMITTED,
//     whatever the server default, so that its locking reads and writes act
//     on the latest committed row: SELECT … FOR UPDATE re-reads a family
//     row, and the UPDATE consuming a code finds a concurrent consumption
//     and reports a replay. synchronous_commit=off can lose an acknowledged
//     revocation in a crash.
//   - MySQL: the tables must use InnoDB (row locks), and lookups must run
//     in autocommit mode — the default — so each one sees the latest
//     commits.
//   - SQLite: one writer at a time. Set a busy timeout (with
//     modernc.org/sqlite, the _pragma=busy_timeout(5000) DSN option) so a
//     concurrent writer waits instead of failing with SQLITE_BUSY; a busy
//     error fails the operation, closed.
//   - Lookups must reach the primary database: a replica DSN or a
//     read/write-splitting proxy could answer from before a revocation.
//
// The CI of this module exercises SQLite only: the PostgreSQL and MySQL
// guarantees rest on the locking described in [Store].
//
// # Cleanup
//
// The store ships no expiry job: rows stay until an operator deletes them.
// A revocation never deletes tokens, and an exchanged authorization code
// keeps its row, flagged consumed, so that a replay of the code is
// recognized; a code never exchanged stays too. Every table carries
// expires_at (Unix seconds), and a family record outlives its tokens — and
// is kept for oauth2.FamilyRevocationRetention after a revocation. Delete
// expired rows ("expires_at < now"; a code past it can no longer be
// exchanged) table by table, in small batches by primary key and outside
// long transactions (autocommit, or READ COMMITTED). Delete families in
// statements of their own: a transaction deleting tokens then families
// takes their locks in the reverse order of the store and can deadlock with
// it. The DDL creates no index — MySQL has no CREATE INDEX IF NOT EXISTS —
// so add one on expires_at through your migration tool: on MySQL, a range
// delete on an unindexed expires_at takes next-key locks that block the
// code and token writes of /authorize and /token.
//
// Never delete a family row before its expires_at. A missing row fails
// closed for lookups — the store treats the tokens of an unknown family as
// revoked — but the next issuance into a family whose revoked row is gone
// records the family active again, reviving its tokens.
//
// Allowed dependencies:
//   - github.com/hyperscale-stack/security/oauth2
//   - database/sql
//   - stdlib only (drivers are pluggable; users bring their own)
package sqlstore
