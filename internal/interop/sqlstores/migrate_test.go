// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstores_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	oauth2sql "github.com/hyperscale-stack/security/oauth2/store/sql"
	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	oidcsql "github.com/hyperscale-stack/security/oidc/client/store/sql"
	samlsp "github.com/hyperscale-stack/security/saml/sp"
	samlsql "github.com/hyperscale-stack/security/saml/sp/store/sql"
	"github.com/stretchr/testify/require"
)

// sqlStore is one of the SQL stores under test.
type sqlStore struct {
	name string
	// module is the store's module path, from which the documented
	// PostgreSQL advisory lock of its Migrate is derived.
	module string
	// tables are the tables its Schema creates, in creation order.
	tables []string
	// migrate runs the store's Migrate on db.
	migrate func(ctx context.Context, db *sql.DB, e engine) error
	// use writes and reads a record, proving the tables serve the store.
	use func(t *testing.T, db *sql.DB, e engine)
}

var sqlStores = []sqlStore{
	{
		name:   "oauth2",
		module: "github.com/hyperscale-stack/security/oauth2/store/sql",
		tables: []string{"oauth2_auth_codes", "oauth2_access_tokens", "oauth2_refresh_tokens", "oauth2_token_families"},
		migrate: func(ctx context.Context, db *sql.DB, e engine) error {
			s, err := oauth2sql.New(db, oauth2Dialect(e))
			if err != nil {
				return err
			}

			return s.Migrate(ctx)
		},
		use: useOAuth2,
	},
	{
		name:   "oidc",
		module: "github.com/hyperscale-stack/security/oidc/client/store/sql",
		tables: []string{"oidc_client_transactions"},
		migrate: func(ctx context.Context, db *sql.DB, e engine) error {
			s, err := oidcsql.New(db, oidcDialect(e))
			if err != nil {
				return err
			}

			return s.Migrate(ctx)
		},
		use: useOIDC,
	},
	{
		name:   "saml",
		module: "github.com/hyperscale-stack/security/saml/sp/store/sql",
		tables: []string{"samlsp_transactions", "samlsp_used_assertions"},
		migrate: func(ctx context.Context, db *sql.DB, e engine) error {
			s, err := samlsql.New(db, samlDialect(e))
			if err != nil {
				return err
			}

			return s.Migrate(ctx)
		},
		use: useSAML,
	},
}

// migrationLock is the PostgreSQL advisory lock the Migrate of the store
// module takes, as its package documentation derives it: the first eight
// bytes of SHA-256("<module path>.Migrate"), big-endian, as a bigint.
func migrationLock(module string) string {
	sum := sha256.Sum256([]byte(module + ".Migrate"))

	return strconv.FormatInt(int64(binary.BigEndian.Uint64(sum[:8])), 10) //nolint:gosec // G115: the bigint key is these 64 bits
}

// sha256Hex returns hex(SHA-256(s)): a store key of the OIDC and SAML
// stores.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))

	return hex.EncodeToString(sum[:])
}

func useOAuth2(t *testing.T, db *sql.DB, e engine) {
	t.Helper()

	s, err := oauth2sql.New(db, oauth2Dialect(e))
	require.NoError(t, err)

	pair := tokenPair(randomName("use-"), randomName("fam-use-"))
	require.NoError(t, s.SaveTokenPair(t.Context(), pair))

	_, err = s.LookupAccessToken(t.Context(), pair.Access.TokenHash)
	require.NoError(t, err)
}

func useOIDC(t *testing.T, db *sql.DB, e engine) {
	t.Helper()

	s, err := oidcsql.New(db, oidcDialect(e))
	require.NoError(t, err)

	seed := randomName("use-")
	now := time.Unix(time.Now().Unix(), 0).UTC()
	tx := &oidcclient.Transaction{
		StateHash: sha256Hex("state-" + seed), BindingHash: sha256Hex("binding-" + seed),
		ConnectionID: "acme", Issuer: "https://idp.example.com", ClientID: "client-1",
		RedirectURI: "https://rp.example.com/oidc/acme/callback", ResponseMode: oidcclient.ResponseModeQuery,
		MaxAge: oidcclient.NoMaxAge, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute),
		Integrity: sha256Hex("integrity-" + seed),
	}
	require.NoError(t, s.Save(t.Context(), tx))

	got, err := s.Consume(t.Context(), tx.StateHash, tx.BindingHash, now)
	require.NoError(t, err)
	require.Equal(t, tx.StateHash, got.StateHash)
}

func useSAML(t *testing.T, db *sql.DB, e engine) {
	t.Helper()

	s, err := samlsql.New(db, samlDialect(e))
	require.NoError(t, err)

	seed := randomName("use-")
	rec := &samlsp.TransactionRecord{
		ID: sha256Hex("id-" + seed), BindingHash: sha256Hex("binding-" + seed), Payload: `{"req":"x"}`,
		ExpiresAt: time.Unix(time.Now().Add(10*time.Minute).Unix(), 0), Integrity: sha256Hex("integrity-" + seed),
	}
	require.NoError(t, s.SaveTransaction(t.Context(), rec))
	require.NoError(t, s.ConsumeTransaction(t.Context(), rec.ID, rec.BindingHash))
}

// tokenPair returns a pair in family: access token "at-<name>" and refresh
// token "rt-<name>".
func tokenPair(name, family string) *oauth2.TokenPair {
	now := time.Now()

	return &oauth2.TokenPair{
		Access: oauth2.AccessToken{
			TokenHash: "at-" + name, ClientID: "client-1", Subject: "alice", Scope: "read", Audience: "api",
			FamilyID: family, IssuedAt: now, ExpiresAt: now.Add(time.Hour), Issuer: "https://issuer.example",
		},
		Refresh: &oauth2.RefreshToken{
			TokenHash: "rt-" + name, ClientID: "client-1", Subject: "alice", Scope: "read",
			FamilyID: family, IssuedAt: now, ExpiresAt: now.Add(24 * time.Hour), Issuer: "https://issuer.example",
		},
	}
}

// tableExists reports whether the namespace db works in holds table.
func tableExists(t *testing.T, db *sql.DB, e engine, table string) bool {
	t.Helper()

	q := `SELECT count(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = $1`

	switch e {
	case engineMySQL:
		q = `SELECT count(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?`
	case engineSQLite:
		q = `SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?`
	}

	var n int
	require.NoError(t, db.QueryRowContext(t.Context(), q, table).Scan(&n))

	return n == 1
}

// requireTables asserts that every table of s exists, or that none does.
func requireTables(t *testing.T, db *sql.DB, e engine, s sqlStore, exist bool) {
	t.Helper()

	for _, table := range s.tables {
		require.Equal(t, exist, tableExists(t, db, e, table), "table %s exists", table)
	}
}

// The size of TestMigrateConcurrently: rounds of instances booting at once
// on an empty database, each Migrate bounded by migrateDeadline, so that a
// Migrate waiting on a lock it never gets fails fast.
const (
	migrateRounds    = 5
	migrateInstances = 12
	migrateDeadline  = 15 * time.Second
)

// TestMigrateConcurrently boots twelve instances at once on an empty
// database — four per store, each with its own connection pool, the three
// stores migrating together — round after round: every Migrate succeeds
// and the tables then serve their store. On PostgreSQL, concurrent CREATE
// TABLE IF NOT EXISTS of one table used to fail on the unique index of
// the catalog's row types (SQLSTATE 23505); the PostgreSQL rounds run at
// the server's default isolation and with SERIALIZABLE as the default.
// MySQL, MariaDB and SQLite (with its busy timeout) serialize the creation
// of a table themselves.
func TestMigrateConcurrently(t *testing.T) {
	for _, b := range []backend{sqliteFile, postgres, postgresSerializable, mysql80, mysql84, mariadb} {
		t.Run(b.name, func(t *testing.T) {
			b.server(t)

			for range migrateRounds {
				migrateTogether(t, b)
			}
		})
	}
}

// migrateTogether runs one round of TestMigrateConcurrently on a new
// namespace of b.
func migrateTogether(t *testing.T, b backend) {
	t.Helper()

	driver, dsn := b.namespace(t)

	pools := make([]*sql.DB, migrateInstances)
	for i := range pools {
		pools[i] = open(t, driver, dsn, 2)
	}

	if b.params != nil {
		var isolation string
		require.NoError(t, pools[0].QueryRowContext(t.Context(), `SHOW default_transaction_isolation`).Scan(&isolation))
		require.Equal(t, b.params["default_transaction_isolation"], isolation)
	}

	var (
		wg    sync.WaitGroup
		start = make(chan struct{})
		errs  = make([]error, migrateInstances)
	)

	for i := range migrateInstances {
		wg.Go(func() {
			<-start

			ctx, cancel := context.WithTimeout(context.Background(), migrateDeadline)
			defer cancel()

			errs[i] = sqlStores[i%len(sqlStores)].migrate(ctx, pools[i], b.engine)
		})
	}

	close(start)
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "Migrate of instance %d (%s)", i, sqlStores[i%len(sqlStores)].name)
	}

	for i, s := range sqlStores {
		requireTables(t, pools[i], b.engine, s, true)
		s.use(t, pools[i], b.engine)
	}

	for _, db := range pools {
		_ = db.Close()
	}
}

// migrateWithin runs the Migrate of s under ctx, and fails t unless it
// returns within limit: a Migrate that ignores its context, waiting for a
// lock it never gets, fails the test instead of hanging it.
func migrateWithin(t *testing.T, ctx context.Context, limit time.Duration, s sqlStore, db *sql.DB) error {
	t.Helper()

	done := make(chan error, 1)

	go func() { done <- s.migrate(ctx, db, enginePostgres) }()

	select {
	case err := <-done:
		return err
	case <-time.After(limit):
		t.Fatalf("%s: Migrate still running after %s: it ignores its context", s.name, limit)

		return nil
	}
}

// holdLock takes the PostgreSQL advisory lock key in a transaction of
// db, which the caller ends.
func holdLock(t *testing.T, db *sql.DB, key string) *sql.Tx {
	t.Helper()

	tx, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback() })

	_, err = tx.ExecContext(t.Context(), "SELECT pg_advisory_xact_lock("+key+")")
	require.NoError(t, err)

	return tx
}

// TestMigrateWaitsForItsLock holds, in another transaction, the advisory
// lock each store's package documentation names: the store's Migrate
// waits for it — until its context ends, having created nothing — while
// the Migrate of another store, whose lock is distinct, goes through;
// once the holder commits, Migrate creates its tables.
func TestMigrateWaitsForItsLock(t *testing.T) {
	postgres.server(t)

	for i, s := range sqlStores {
		t.Run(s.name, func(t *testing.T) {
			driver, dsn := postgres.namespace(t)
			db := open(t, driver, dsn, 2)
			holder := holdLock(t, open(t, driver, dsn, 1), migrationLock(s.module))

			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()

			require.ErrorIs(t, migrateWithin(t, ctx, 10*time.Second, s, db), context.DeadlineExceeded)
			requireTables(t, db, enginePostgres, s, false)

			// Bounded: a store sharing the held lock would wait for good.
			otherCtx, cancelOther := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancelOther()

			other := sqlStores[(i+1)%len(sqlStores)]
			require.NoError(t, migrateWithin(t, otherCtx, 15*time.Second, other, db), "%s's lock is not %s's", other.name, s.name)
			requireTables(t, db, enginePostgres, other, true)

			require.NoError(t, holder.Commit())
			require.NoError(t, s.migrate(t.Context(), db, enginePostgres))
			requireTables(t, db, enginePostgres, s, true)
		})
	}
}

// TestMigrateFailureCreatesNothing makes the creation of each store's last
// table fail on PostgreSQL — an enum type named like the table already
// exists, so the table's row type cannot be created (a composite type
// would not do: it is a relation, which IF NOT EXISTS skips) — and checks
// that Migrate, which runs in one transaction there, leaves none of the
// store's tables behind. Run under a context that never ends, the usual
// call at boot, the failed Migrate also ends its transaction: its
// connection goes back to the pool — not left "idle in transaction
// (aborted)" — and, on a one-connection pool, the next Migrate goes
// through once the cause is gone.
func TestMigrateFailureCreatesNothing(t *testing.T) {
	postgres.server(t)

	for _, s := range sqlStores {
		t.Run(s.name, func(t *testing.T) {
			driver, dsn := postgres.namespace(t)
			admin := open(t, driver, dsn, 1)
			db := open(t, driver, dsn, 1)

			blocker := s.tables[len(s.tables)-1]
			_, err := admin.ExecContext(t.Context(), "CREATE TYPE "+blocker+" AS ENUM ('taken')")
			require.NoError(t, err)

			require.Error(t, s.migrate(context.Background(), db, enginePostgres))
			requireTables(t, admin, enginePostgres, s, false)
			require.Zero(t, db.Stats().InUse, "the failed Migrate gave its connection back")

			var aborted int
			require.NoError(t, admin.QueryRowContext(t.Context(), `SELECT count(*) FROM pg_stat_activity
				WHERE datname = current_database() AND state = 'idle in transaction (aborted)'`).Scan(&aborted))
			require.Zero(t, aborted, "backends left idle in transaction (aborted)")

			_, err = admin.ExecContext(t.Context(), "DROP TYPE "+blocker)
			require.NoError(t, err)

			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()

			require.NoError(t, migrateWithin(t, ctx, 15*time.Second, s, db), "the next Migrate on the same pool")
			requireTables(t, admin, enginePostgres, s, true)
		})
	}
}
