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
// and [Store.Migrate] wrap it with the requirement and the table, column
// or setting at fault.
var ErrDeploymentRequirement = errors.New("sqlstore: deployment requirement not met")

// CheckDeployment verifies the deployment requirements of the package
// documentation that the database reports, and returns every one it finds
// unmet — each matching [ErrDeploymentRequirement] — or the error of the
// database. On MySQL and MariaDB:
//
//   - every table of the store exists in the connection's database and
//     uses InnoDB, whose transactions and row locks the token-family
//     contract of [oauth2.Storage] rests on (atomic writes, I3);
//   - the six key columns are VARBINARY, compared byte for byte;
//   - the connection's sql_mode is strict (STRICT_TRANS_TABLES or
//     STRICT_ALL_TABLES): a non-strict session truncates an over-long
//     subject, client ID or extension data instead of refusing it.
//
// PostgreSQL and SQLite report nothing it checks (see [Postgres] and
// [SQLite]). [Store.Migrate] calls it once the tables exist; when you apply
// [Schema] with your own migration tool, call it at boot, before serving
// traffic. It reads information_schema and the session's sql_mode, on one
// pooled connection: set the strict mode for every connection — the
// server's default, or the DSN — never per session.
func (s *Store) CheckDeployment(ctx context.Context) error {
	return s.dialect.checkDeployment(ctx, s.db)
}

// querier runs the queries of a deployment check: the store's *sql.DB, or
// the *sql.Conn of a Migrate holding its named lock.
type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// storeTables are the tables of the store, in [Schema]'s order.
var storeTables = []string{"oauth2_auth_codes", "oauth2_access_tokens", "oauth2_refresh_tokens", "oauth2_token_families"}

// keyColumns are the columns the statements compare, as table.column: the
// columns [Schema] declares VARBINARY on MySQL.
var keyColumns = []string{
	"oauth2_auth_codes.code_hash",
	"oauth2_access_tokens.token_hash", "oauth2_access_tokens.family_id",
	"oauth2_refresh_tokens.token_hash", "oauth2_refresh_tokens.family_id",
	"oauth2_token_families.family_id",
}

// The statements of the MySQL check, on the tables of storeTables.
const (
	selectEngines = `SELECT TABLE_NAME, COALESCE(ENGINE, '') FROM information_schema.TABLES
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME IN (?, ?, ?, ?)`
	selectColumnTypes = `SELECT CONCAT(TABLE_NAME, '.', COLUMN_NAME), DATA_TYPE FROM information_schema.COLUMNS
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME IN (?, ?, ?, ?)`
	selectSQLMode = `SELECT @@SESSION.sql_mode`
)

// checkMySQL reads what the requirements of a MySQL deployment depend on,
// then checks it.
func checkMySQL(ctx context.Context, q querier) error {
	tables := make([]any, len(storeTables))
	for i, table := range storeTables {
		tables[i] = table
	}

	engines, err := queryPairs(ctx, q, selectEngines, tables...)
	if err != nil {
		return fmt.Errorf("sqlstore: check deployment: storage engines: %w", err)
	}

	types, err := queryPairs(ctx, q, selectColumnTypes, tables...)
	if err != nil {
		return fmt.Errorf("sqlstore: check deployment: column types: %w", err)
	}

	var mode string
	if err := q.QueryRowContext(ctx, selectSQLMode).Scan(&mode); err != nil {
		return fmt.Errorf("sqlstore: check deployment: sql_mode: %w", err)
	}

	return errors.Join(checkEngines(storeTables, engines), checkKeyColumns(engines, types), checkSQLMode(mode))
}

// queryPairs runs query and returns its two-column rows as a map.
func queryPairs(ctx context.Context, q querier, query string, args ...any) (map[string]string, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err //nolint:wrapcheck // wrapped by the caller
	}

	defer func() { _ = rows.Close() }()

	pairs := map[string]string{}

	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err //nolint:wrapcheck // wrapped by the caller
		}

		pairs[key] = value
	}

	return pairs, rows.Err() //nolint:wrapcheck // wrapped by the caller
}

// checkEngines reports each of tables that engines — table name → storage
// engine — does not list, or lists with another engine than InnoDB.
func checkEngines(tables []string, engines map[string]string) error {
	var errs []error

	for _, table := range tables {
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

// checkKeyColumns reports each key column of a table engines lists whose
// type — in types, table.column → type — is not varbinary.
func checkKeyColumns(engines, types map[string]string) error {
	var errs []error

	for _, column := range keyColumns {
		table, _, _ := strings.Cut(column, ".")
		if _, ok := engines[table]; !ok {
			continue // reported by checkEngines
		}

		switch dataType, ok := types[column]; {
		case !ok:
			errs = append(errs, fmt.Errorf("%w: column %s not found", ErrDeploymentRequirement, column))
		case !strings.EqualFold(dataType, "varbinary"):
			errs = append(errs, fmt.Errorf("%w: column %s is %s, not varbinary: keys would be compared under a collation",
				ErrDeploymentRequirement, column, strings.ToLower(dataType)))
		}
	}

	return errors.Join(errs...)
}

// checkSQLMode reports a sql_mode without STRICT_TRANS_TABLES nor
// STRICT_ALL_TABLES.
func checkSQLMode(mode string) error {
	for flag := range strings.SplitSeq(mode, ",") {
		switch strings.ToUpper(strings.TrimSpace(flag)) {
		case "STRICT_TRANS_TABLES", "STRICT_ALL_TABLES":
			return nil
		}
	}

	return fmt.Errorf("%w: sql_mode %q is not strict (STRICT_TRANS_TABLES or STRICT_ALL_TABLES): an over-long value would be truncated",
		ErrDeploymentRequirement, mode)
}
