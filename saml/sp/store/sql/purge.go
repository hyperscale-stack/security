// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// purgeBatch is the most rows one purge statement deletes: a batch keeps
// the rows it deletes locked until it commits, so a backlog goes in short
// transactions. A variable, for the tests.
var purgeBatch = 1000

// The purge statements of PostgreSQL and SQLite, one per table, with ? for
// (before, limit, before): the outer DELETE re-checks the expiry of each
// row on its latest version.
var purgeSubqueries = []string{
	`DELETE FROM samlsp_transactions WHERE id IN
		(SELECT id FROM samlsp_transactions WHERE expires_at < ? LIMIT ?) AND expires_at < ?`,
	`DELETE FROM samlsp_used_assertions WHERE assertion_key IN
		(SELECT assertion_key FROM samlsp_used_assertions WHERE expires_at < ? LIMIT ?) AND expires_at < ?`,
}

// PurgeExpired deletes the transactions and replay marks whose expiry is
// before now, and returns how many it deleted. Nothing else deletes them:
// schedule it, every few minutes for instance. Concurrent purges are safe.
// A row is deleted only after its expiry — a replay mark is kept at least
// until then — which changes nothing: an expired transaction is refused
// anyway, and an assertion is never accepted past its mark's expiry. Pass
// the current time: a later instant would delete marks still due.
//
// Each table is purged in batches of at most 1000 rows, each a transaction
// of its own at READ COMMITTED on PostgreSQL and MySQL. On MySQL, READ
// COMMITTED keeps a batch from locking the gaps it scans, which would block
// the inserts of logins starting and assertions consumed meanwhile; a
// server logging statements (binlog_format=STATEMENT) refuses it, and the
// purge fails, closed. Add an index on expires_at to both tables (see the
// package documentation). A failure returns the rows deleted until then
// and the error.
func (s *Store) PurgeExpired(ctx context.Context, now time.Time) (int64, error) {
	var total int64

	for _, stmt := range s.dialect.purgeStatements() {
		for {
			n, err := s.purgeOnce(ctx, stmt, now.Unix())
			total += n

			if err != nil {
				return total, err
			}

			if n < int64(purgeBatch) {
				break
			}
		}
	}

	return total, nil
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

// readCommitted are the options of a purge batch on PostgreSQL and MySQL.
var readCommitted = &sql.TxOptions{Isolation: sql.LevelReadCommitted}
