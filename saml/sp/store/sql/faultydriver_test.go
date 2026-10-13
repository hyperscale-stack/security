// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"testing"

	samlsp "github.com/hyperscale-stack/security/saml/sp"
	sqlstore "github.com/hyperscale-stack/security/saml/sp/store/sql"
	"github.com/stretchr/testify/require"
)

// faultyConn is a database/sql connection whose statements fail as
// configured, for failures SQLite cannot produce on demand.
type faultyConn struct {
	execErr, rowsAffectedErr, queryErr error
}

func (c *faultyConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("faulty: no prepare")
}
func (c *faultyConn) Close() error { return nil }

// Begin opens a transaction whose statements go through the connection,
// failing as configured.
func (c *faultyConn) Begin() (driver.Tx, error) { return faultyTx{}, nil }

// faultyTx commits and rolls back nothing.
type faultyTx struct{}

func (faultyTx) Commit() error   { return nil }
func (faultyTx) Rollback() error { return nil }

func (c *faultyConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	if c.execErr != nil {
		return nil, c.execErr
	}

	return faultyResult{err: c.rowsAffectedErr}, nil
}

func (c *faultyConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return nil, c.queryErr
}

// faultyResult reports zero affected rows, or err.
type faultyResult struct{ err error }

func (r faultyResult) LastInsertId() (int64, error) { return 0, errors.New("faulty: no insert ID") }
func (r faultyResult) RowsAffected() (int64, error) { return 0, r.err }

// faultyConnector serves one faultyConn.
type faultyConnector struct{ conn *faultyConn }

func (c faultyConnector) Connect(context.Context) (driver.Conn, error) { return c.conn, nil }
func (c faultyConnector) Driver() driver.Driver                        { return faultyDriver{c.conn} }

type faultyDriver struct{ conn *faultyConn }

func (d faultyDriver) Open(string) (driver.Conn, error) { return d.conn, nil }

func openFaulty(t *testing.T, conn *faultyConn) *sqlstore.Store {
	t.Helper()

	return openFaultyDialect(t, conn, sqlstore.Postgres)
}

func openFaultyDialect(t *testing.T, conn *faultyConn, d sqlstore.Dialect) *sqlstore.Store {
	t.Helper()

	db := sql.OpenDB(faultyConnector{conn: conn})
	t.Cleanup(func() { _ = db.Close() })

	store, err := sqlstore.New(db, d)
	require.NoError(t, err)

	return store
}

// TestMigrateFailure: a failing statement fails Migrate, on the locked
// path (PostgreSQL: the advisory lock is the first statement) and on the
// per-statement one (SQLite).
func TestMigrateFailure(t *testing.T) {
	t.Parallel()

	for _, d := range []sqlstore.Dialect{sqlstore.Postgres, sqlstore.SQLite} {
		store := openFaultyDialect(t, &faultyConn{execErr: errors.New("permission denied")}, d)
		require.ErrorContains(t, store.Migrate(context.Background()), "permission denied", d.Name())
	}
}

func TestConsumeClassificationFailures(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// The driver cannot count the updated rows.
	store := openFaulty(t, &faultyConn{rowsAffectedErr: errors.New("no row count")})
	err := store.ConsumeTransaction(ctx, key("x"), key("b"))
	require.ErrorContains(t, err, "no row count")
	require.NotErrorIs(t, err, samlsp.ErrRejected)

	// Nothing was updated and the classification read fails.
	store = openFaulty(t, &faultyConn{queryErr: errors.New("connection lost")})
	err = store.ConsumeTransaction(ctx, key("x"), key("b"))
	require.ErrorContains(t, err, "connection lost")
	require.NotErrorIs(t, err, samlsp.ErrRejected, "an unclassified failure is not a rejection")
}
