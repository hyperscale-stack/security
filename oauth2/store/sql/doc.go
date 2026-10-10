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
//   - PostgreSQL: the store runs its transactions at READ COMMITTED,
//     whatever the server default, so that SELECT … FOR UPDATE re-reads the
//     latest committed family row. synchronous_commit=off can lose an
//     acknowledged revocation in a crash.
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
// A revocation never deletes tokens and the store ships no expiry job:
// rows stay until an operator deletes them. Every table carries expires_at
// (Unix seconds), and a family record outlives its tokens — and is kept for
// oauth2.FamilyRevocationRetention after a revocation. Delete expired rows
// ("expires_at < now") table by table, in small batches by primary key and
// outside long transactions (autocommit, or READ COMMITTED). Delete families
// in statements of their own: a transaction deleting tokens then families
// takes their locks in the reverse order of the store and can deadlock with
// it. On MySQL, a range delete on the unindexed expires_at column takes
// next-key locks: index it, or delete by primary key. Deleting a family
// record early is safe — the store treats the tokens of an unknown family as
// revoked — but logs their users out.
//
// Allowed dependencies:
//   - github.com/hyperscale-stack/security/oauth2
//   - database/sql
//   - stdlib only (drivers are pluggable; users bring their own)
package sqlstore
