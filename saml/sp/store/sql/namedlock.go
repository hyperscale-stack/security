// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"math"
	"time"
)

// migrationLockName is the named lock Migrate takes on MySQL and
// MariaDB (GET_LOCK): the module path without its host, then ".Migrate".
// Named locks are server-wide and each store module has its own, so that
// their migrations never wait for one another.
const migrationLockName = "hyperscale-stack/security/saml/sp/store/sql.Migrate"

// lockWaitForever is the GET_LOCK timeout, in seconds, under a context
// without deadline: a year — the wait lasts as long as the context does.
const lockWaitForever = 365 * 24 * 60 * 60

// releaseTimeout bounds the release of a named lock, which runs even once
// the context of Migrate has ended.
const releaseTimeout = 10 * time.Second

// lockWaitSeconds is the GET_LOCK timeout under ctx: the seconds left until
// its deadline, rounded up and at least one, or lockWaitForever.
func lockWaitSeconds(ctx context.Context) int64 {
	deadline, ok := ctx.Deadline()
	if !ok {
		return lockWaitForever
	}

	return max(1, int64(math.Ceil(time.Until(deadline).Seconds())))
}

// migrateUnderNamedLock applies Schema and runs the deployment check on
// one connection holding the named lock name, which it releases before the
// connection goes back to the pool: concurrent calls run one after the
// other.
func (s *Store) migrateUnderNamedLock(ctx context.Context, name string) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("sqlstore: migrate: connection: %w", err)
	}

	defer func() { _ = conn.Close() }()

	if err := acquireNamedLock(ctx, conn, name); err != nil {
		return err
	}

	defer releaseNamedLock(ctx, conn, name)

	for _, stmt := range Schema(s.dialect) {
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("sqlstore: migrate: %w", err)
		}
	}

	return s.dialect.checkDeployment(ctx, conn)
}

// acquireNamedLock takes the named lock name on conn, waiting as long as
// ctx allows: the server's wait is bounded by its deadline, and the driver
// cancels it when ctx ends.
func acquireNamedLock(ctx context.Context, conn *sql.Conn, name string) error {
	var granted sql.NullInt64

	if err := conn.QueryRowContext(ctx, `SELECT GET_LOCK(?, ?)`, name, lockWaitSeconds(ctx)).Scan(&granted); err != nil {
		// The server may have granted the lock before the reply was lost:
		// never pool a session that may hold it.
		discard(conn)

		return fmt.Errorf("sqlstore: migrate: lock %s: %w", name, err)
	}

	switch {
	case !granted.Valid:
		return fmt.Errorf("sqlstore: migrate: lock %s: not granted", name)
	case granted.Int64 != 1:
		return fmt.Errorf("sqlstore: migrate: lock %s: %w", name, context.DeadlineExceeded)
	default:
		return nil
	}
}

// releaseNamedLock releases the named lock name held on conn, even once
// ctx has ended. A release that fails discards the connection: its session
// would otherwise keep the lock from the pool.
func releaseNamedLock(ctx context.Context, conn *sql.Conn, name string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), releaseTimeout)
	defer cancel()

	var released sql.NullInt64

	err := conn.QueryRowContext(ctx, `SELECT RELEASE_LOCK(?)`, name).Scan(&released)
	if err == nil && released.Valid && released.Int64 == 1 {
		return
	}

	discard(conn)
}

// discard closes conn instead of returning it to the pool when it is
// closed.
func discard(conn *sql.Conn) {
	_ = conn.Raw(func(any) error { return driver.ErrBadConn })
}
