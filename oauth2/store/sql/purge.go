// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore

import (
	"context"
	"fmt"
	"time"
)

// purgeBatch is the most rows one purge statement deletes: a batch keeps
// the rows it deletes locked until it commits, so a backlog goes in short
// transactions. A variable, for the tests.
var purgeBatch = 1000

// The purge statements of PostgreSQL and SQLite, one per table in purge
// order — codes and tokens, then families — with ? for (before, limit,
// before). The outer DELETE repeats the expiry: a row the subquery picked,
// then extended by a concurrent transaction — a revocation extending its
// family's retention — is re-checked on its latest version and kept.
const (
	purgeCodesSubquery = `DELETE FROM oauth2_auth_codes WHERE code_hash IN
		(SELECT code_hash FROM oauth2_auth_codes WHERE expires_at < ? LIMIT ?) AND expires_at < ?`
	purgeAccessSubquery = `DELETE FROM oauth2_access_tokens WHERE token_hash IN
		(SELECT token_hash FROM oauth2_access_tokens WHERE expires_at < ? LIMIT ?) AND expires_at < ?`
	purgeRefreshSubquery = `DELETE FROM oauth2_refresh_tokens WHERE token_hash IN
		(SELECT token_hash FROM oauth2_refresh_tokens WHERE expires_at < ? LIMIT ?) AND expires_at < ?`
	purgeFamiliesSubquery = `DELETE FROM oauth2_token_families WHERE family_id IN
		(SELECT family_id FROM oauth2_token_families WHERE expires_at < ? LIMIT ?) AND expires_at < ?`
)

// purgeSubqueries are the purge statements of PostgreSQL and SQLite.
var purgeSubqueries = []string{purgeCodesSubquery, purgeAccessSubquery, purgeRefreshSubquery, purgeFamiliesSubquery}

// subqueryArgs are the arguments of a purge statement of purgeSubqueries.
func subqueryArgs(before int64, limit int) []any { return []any{before, limit, before} }

// PurgeExpired deletes the rows whose expires_at is before now — codes,
// access and refresh tokens, then token families past their retention —
// and returns how many it deleted. Nothing else deletes them: schedule it,
// every few minutes for instance. Concurrent purges are safe.
//
// Pass the current time: a later instant deletes live rows, and a token
// family deleted before its expires_at is recorded active again by the
// next issuance into it, reviving the tokens a revocation covered (see the
// package documentation).
//
// Each table is purged in batches of at most 1000 rows, each a transaction
// of its own — at READ COMMITTED on PostgreSQL and MySQL — codes and tokens
// before families, the order in which no batch can deadlock with the
// store's transactions. A batch re-checks the expiry of each row it
// deletes on its latest version, so a family whose retention a concurrent
// revocation extends is kept. On MySQL, READ COMMITTED keeps a batch from
// locking the gaps it scans, which would block the inserts of /authorize
// and /token; a server logging statements (binlog_format=STATEMENT)
// refuses it, and the purge fails, closed. Add an index on expires_at to
// each table (see the package documentation): without it every batch
// scans its table.
//
// A failure returns the rows deleted until then and the error; the
// batches committed before it stay committed.
func (s *Store) PurgeExpired(ctx context.Context, now time.Time) (int64, error) {
	var total int64

	for _, stmt := range s.dialect.purgeStatements() {
		n, err := s.purgeTable(ctx, stmt, now.Unix())
		total += n

		if err != nil {
			return total, err
		}
	}

	return total, nil
}

// purgeTable runs the purge statement of one table, batch after batch,
// until a batch deletes fewer rows than purgeBatch.
func (s *Store) purgeTable(ctx context.Context, stmt string, before int64) (int64, error) {
	var total int64

	for {
		n, err := s.purgeOnce(ctx, stmt, before)
		total += n

		if err != nil || n < int64(purgeBatch) {
			return total, err
		}
	}
}

// purgeOnce runs one batch of stmt in a transaction of its own.
func (s *Store) purgeOnce(ctx context.Context, stmt string, before int64) (int64, error) {
	tx, err := s.db.BeginTx(ctx, s.dialect.purgeTxOptions())
	if err != nil {
		return 0, fmt.Errorf("sqlstore: purge expired rows: begin: %w", err)
	}

	defer func() { _ = tx.Rollback() }() // a no-op once committed

	res, err := tx.ExecContext(ctx, s.dialect.rebind(stmt), s.dialect.purgeArgs(before, purgeBatch)...)
	if err != nil {
		return 0, fmt.Errorf("sqlstore: purge expired rows: %w", err)
	}

	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("sqlstore: purge expired rows: rows affected: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("sqlstore: purge expired rows: commit: %w", err)
	}

	return n, nil
}
