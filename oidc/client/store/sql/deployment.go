// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// ErrDeploymentRequirement reports a deployment requirement of the package
// documentation that the database does not meet. [Store.CheckDeployment]
// and [Store.Migrate] wrap it with the requirement and the table at fault.
var ErrDeploymentRequirement = errors.New("sqlstore: deployment requirement not met")

// CheckDeployment verifies the deployment requirement of the package
// documentation that the database reports, and returns an error matching
// [ErrDeploymentRequirement] when it is not met — or the error of the
// database. On MySQL and MariaDB, oidc_client_transactions exists in the
// connection's database and uses InnoDB, whose row locks Consume takes and
// whose crash safety keeps a consumption once acknowledged. PostgreSQL and
// SQLite report nothing it checks. [Store.Migrate] calls it once the table
// exists; when you apply [Schema] with your own migration tool, call it at
// boot, before serving traffic.
func (s *Store) CheckDeployment(ctx context.Context) error {
	return s.dialect.checkDeployment(ctx, s.db)
}

// querier runs the queries of a deployment check: the store's *sql.DB, or
// the *sql.Conn of a Migrate holding its named lock.
type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// storeTable is the table of the store.
const storeTable = "oidc_client_transactions"

// selectEngine reads the storage engine of storeTable.
const selectEngine = `SELECT COALESCE(ENGINE, '') FROM information_schema.TABLES
	WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?`

// checkMySQL reads the storage engine of the store's table, then checks it.
func checkMySQL(ctx context.Context, q querier) error {
	var engine string

	err := q.QueryRowContext(ctx, selectEngine, storeTable).Scan(&engine)

	switch {
	case errors.Is(err, sql.ErrNoRows):
		return checkEngine("", false)
	case err != nil:
		return fmt.Errorf("sqlstore: check deployment: storage engine: %w", err)
	default:
		return checkEngine(engine, true)
	}
}

// checkEngine reports a store table that is missing, or whose engine is
// not InnoDB.
func checkEngine(engine string, found bool) error {
	switch {
	case !found:
		return fmt.Errorf("%w: table %s not found in the connection's database", ErrDeploymentRequirement, storeTable)
	case !strings.EqualFold(engine, "InnoDB"):
		return fmt.Errorf("%w: table %s uses the %s engine, not InnoDB", ErrDeploymentRequirement, storeTable, engine)
	default:
		return nil
	}
}
