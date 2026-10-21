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
// documentation that the database does not meet. CheckDeployment and
// Migrate wrap it with the requirement and the table at fault.
var ErrDeploymentRequirement = errors.New("sqlstore: deployment requirement not met")

// CheckDeployment verifies the deployment requirement of the package
// documentation that the database reports, and returns every table that
// does not meet it — each matching ErrDeploymentRequirement — or the error
// of the database. On MySQL and MariaDB, both tables exist in the
// connection's database and use InnoDB, whose crash safety keeps a
// consumption or a replay mark once acknowledged. PostgreSQL and SQLite
// report nothing it checks. Migrate calls it once the tables exist; when
// you apply Schema with your own migration tool, call it at boot, before
// serving traffic.
func (s *Store) CheckDeployment(ctx context.Context) error {
	return s.dialect.checkDeployment(ctx, s.db)
}

// storeTables are the tables of the store, in Schema's order.
var storeTables = []string{"samlsp_transactions", "samlsp_used_assertions"}

// selectEngines reads the storage engine of the tables of storeTables.
const selectEngines = `SELECT TABLE_NAME, COALESCE(ENGINE, '') FROM information_schema.TABLES
	WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME IN (?, ?)`

// checkMySQL reads the storage engines of the store's tables, then checks
// them.
func checkMySQL(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, selectEngines, storeTables[0], storeTables[1])
	if err != nil {
		return fmt.Errorf("sqlstore: check deployment: storage engines: %w", err)
	}

	defer func() { _ = rows.Close() }()

	engines := map[string]string{}

	for rows.Next() {
		var table, engine string
		if err := rows.Scan(&table, &engine); err != nil {
			return fmt.Errorf("sqlstore: check deployment: storage engines: %w", err)
		}

		engines[table] = engine
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("sqlstore: check deployment: storage engines: %w", err)
	}

	return checkEngines(engines)
}

// checkEngines reports each store table that engines — table name →
// storage engine — does not list, or lists with another engine than
// InnoDB.
func checkEngines(engines map[string]string) error {
	var errs []error

	for _, table := range storeTables {
		engine, ok := engines[table]

		switch {
		case !ok:
			errs = append(errs, fmt.Errorf("%w: table %s not found in the connection's database", ErrDeploymentRequirement, table))
		case !strings.EqualFold(engine, "InnoDB"):
			errs = append(errs, fmt.Errorf("%w: table %s uses the %s engine, not InnoDB", ErrDeploymentRequirement, table, engine))
		}
	}

	return errors.Join(errs...)
}
