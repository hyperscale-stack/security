// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstores_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	oauth2sql "github.com/hyperscale-stack/security/oauth2/store/sql"
	oidcsql "github.com/hyperscale-stack/security/oidc/client/store/sql"
	samlsql "github.com/hyperscale-stack/security/saml/sp/store/sql"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

// The real backends are opt-in — routine CI never sets these variables.
// Start them with compose.yaml (see its header), then:
//
//	SQLSTORES_POSTGRES_DSN=postgres://sqlstores:$SQLSTORES_DB_PASSWORD@127.0.0.1:35432/sqlstores?sslmode=disable
//	SQLSTORES_MYSQL80_DSN=root:$SQLSTORES_DB_PASSWORD@tcp(127.0.0.1:33306)/
//	SQLSTORES_MYSQL84_DSN=root:$SQLSTORES_DB_PASSWORD@tcp(127.0.0.1:33307)/
//	SQLSTORES_MARIADB_DSN=root:$SQLSTORES_DB_PASSWORD@tcp(127.0.0.1:33308)/
//
// Every test works in a namespace it creates — a PostgreSQL schema, a
// MySQL database, a SQLite file — and drops the server ones afterwards:
// point the variables at disposable servers all the same. The real-backend
// tests run one after the other, to bound the connections.
const (
	envPostgresDSN = "SQLSTORES_POSTGRES_DSN"
	envMySQL80DSN  = "SQLSTORES_MYSQL80_DSN"
	envMySQL84DSN  = "SQLSTORES_MYSQL84_DSN"
	envMariaDBDSN  = "SQLSTORES_MARIADB_DSN"
)

// engine is the SQL dialect a backend speaks.
type engine int

const (
	engineSQLite engine = iota
	enginePostgres
	engineMySQL
)

// backend is a database server the stores run on.
type backend struct {
	name   string
	engine engine
	// env names the variable holding the server's DSN; SQLite needs none.
	env string
	// params are run-time parameters every PostgreSQL namespace DSN sets.
	params map[string]string
	// clientFoundRows sets the MySQL CLIENT_FOUND_ROWS flag, under which
	// an UPDATE reports the rows it matched rather than those it changed.
	clientFoundRows bool
}

var (
	sqliteFile = backend{name: "sqlite", engine: engineSQLite}
	postgres   = backend{name: "postgres", engine: enginePostgres, env: envPostgresDSN}
	// postgresSerializable makes SERIALIZABLE the default isolation of
	// every transaction that does not choose its own.
	postgresSerializable = backend{
		name: "postgres-serializable", engine: enginePostgres, env: envPostgresDSN,
		params: map[string]string{"default_transaction_isolation": "serializable"},
	}
	mysql80 = backend{name: "mysql80", engine: engineMySQL, env: envMySQL80DSN}
	mysql84 = backend{name: "mysql84", engine: engineMySQL, env: envMySQL84DSN}
	mariadb = backend{name: "mariadb", engine: engineMySQL, env: envMariaDBDSN}
)

// server returns the DSN of b's server, and skips t when b is an opt-in
// backend whose variable is not set.
func (b backend) server(t *testing.T) string {
	t.Helper()

	if b.engine == engineSQLite {
		return ""
	}

	dsn := os.Getenv(b.env)
	if dsn == "" {
		t.Skipf("set %s to run against a real %s (opt-in)", b.env, b.name)
	}

	return dsn
}

// namespace creates an empty namespace on b and returns the driver and the
// DSN of connections into it.
func (b backend) namespace(t *testing.T) (driver, dsn string) {
	t.Helper()

	switch b.engine {
	case enginePostgres:
		return "pgx", b.postgresNamespace(t)
	case engineMySQL:
		return "mysql", b.mysqlNamespace(t)
	default:
		return "sqlite", sqliteNamespace(t)
	}
}

// randomName returns prefix followed by 10 random hex digits.
func randomName(prefix string) string {
	b := make([]byte, 5)
	_, _ = rand.Read(b)

	return prefix + hex.EncodeToString(b)
}

// admin runs one statement on the server dsn designates, on a connection
// of its own.
func admin(driver, dsn, stmt string) error {
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return err
	}

	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err = db.ExecContext(ctx, stmt)

	return err
}

// postgresNamespace works in a new schema, selected through the
// search_path run-time parameter of a URL DSN.
func (b backend) postgresNamespace(t *testing.T) string {
	t.Helper()

	server := b.server(t)
	schema := randomName("sqlstores_")

	require.NoError(t, admin("pgx", server, "CREATE SCHEMA "+schema))
	t.Cleanup(func() { _ = admin("pgx", server, "DROP SCHEMA "+schema+" CASCADE") })

	u, err := url.Parse(server)
	require.NoError(t, err, "%s must be a URL (postgres://…)", b.env)

	q := u.Query()
	q.Set("search_path", schema)

	for name, value := range b.params {
		q.Set(name, value)
	}

	u.RawQuery = q.Encode()

	return u.String()
}

// mysqlNamespace works in a new database.
func (b backend) mysqlNamespace(t *testing.T) string {
	t.Helper()

	server := b.server(t)
	database := randomName("sqlstores_")

	require.NoError(t, admin("mysql", server, "CREATE DATABASE "+database))
	t.Cleanup(func() { _ = admin("mysql", server, "DROP DATABASE "+database) })

	cfg, err := mysqldriver.ParseDSN(server)
	require.NoError(t, err)

	cfg.DBName = database
	cfg.ClientFoundRows = b.clientFoundRows

	return cfg.FormatDSN()
}

// sqliteNamespace works in a new database file in WAL mode, with the busy
// timeout the stores require: concurrent writers wait for the write lock
// instead of failing with SQLITE_BUSY. The file is created, and switched
// to WAL, before any test connection opens it.
func sqliteNamespace(t *testing.T) string {
	t.Helper()

	dsn := "file:" + filepath.Join(t.TempDir(), "stores.db") + "?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)"
	open(t, "sqlite", dsn, 1)

	return dsn
}

// open returns a pool of at most maxConns connections on dsn, closed when
// the test ends, after checking that it reaches the server.
func open(t *testing.T, driver, dsn string, maxConns int) *sql.DB {
	t.Helper()

	db, err := sql.Open(driver, dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	db.SetMaxOpenConns(maxConns)
	db.SetMaxIdleConns(maxConns)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	require.NoError(t, db.PingContext(ctx), "reaching %s", driver)

	return db
}

func oauth2Dialect(e engine) oauth2sql.Dialect {
	switch e {
	case enginePostgres:
		return oauth2sql.Postgres
	case engineMySQL:
		return oauth2sql.MySQL
	default:
		return oauth2sql.SQLite
	}
}

func oidcDialect(e engine) oidcsql.Dialect {
	switch e {
	case enginePostgres:
		return oidcsql.Postgres
	case engineMySQL:
		return oidcsql.MySQL
	default:
		return oidcsql.SQLite
	}
}

func samlDialect(e engine) samlsql.Dialect {
	switch e {
	case enginePostgres:
		return samlsql.Postgres
	case engineMySQL:
		return samlsql.MySQL
	default:
		return samlsql.SQLite
	}
}
