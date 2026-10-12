// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcstack_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	redisstore "github.com/hyperscale-stack/security/oidc/client/store/redis"
	sqlstore "github.com/hyperscale-stack/security/oidc/client/store/sql"
	"github.com/hyperscale-stack/security/oidc/client/storetest"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

// The real backends are opt-in — routine CI never sets these variables.
// Start them with compose.yaml (see its header), then:
//
//	OIDCCLIENT_POSTGRES_DSN=postgres://oidcclient:$OIDCCLIENT_DB_PASSWORD@127.0.0.1:25432/oidcclient?sslmode=disable
//	OIDCCLIENT_MYSQL_DSN=root:$OIDCCLIENT_DB_PASSWORD@tcp(127.0.0.1:23306)/oidcclient
//	OIDCCLIENT_REDIS_ADDR=127.0.0.1:26379
//
// Every test works in a namespace it creates — a PostgreSQL schema, a MySQL
// database, a Redis key prefix — and drops the SQL ones afterwards: point
// the variables at disposable servers all the same.
const (
	envPostgresDSN = "OIDCCLIENT_POSTGRES_DSN"
	envMySQLDSN    = "OIDCCLIENT_MYSQL_DSN"
	envRedisAddr   = "OIDCCLIENT_REDIS_ADDR"
)

// maxPoolConns bounds the connections of every pool the tests open.
const maxPoolConns = 8

// backend is a real server the transaction stores run on.
type backend struct {
	name string
	env  string
	// namespace creates an empty namespace on the server and returns a
	// function opening one more store instance on it — with its own
	// connection pool, like another replica of the application.
	namespace func(t *testing.T, dsn string) func() oidcclient.TransactionStore
}

var backends = []backend{
	{"postgres", envPostgresDSN, postgresNamespace},
	{"mysql", envMySQLDSN, mysqlNamespace},
	{"redis", envRedisAddr, redisNamespace},
}

// randomName returns prefix followed by 8 random hex digits.
func randomName(prefix string) string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)

	return prefix + hex.EncodeToString(b)
}

func openDB(t *testing.T, driver, dsn string) *sql.DB {
	t.Helper()

	db, err := sql.Open(driver, dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	// Bounded pools: the races queue on them instead of exhausting the
	// server's connections, and an idle pool keeps one connection.
	db.SetMaxOpenConns(maxPoolConns)
	db.SetMaxIdleConns(1)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	require.NoError(t, db.PingContext(ctx), "reaching %s", driver)

	return db
}

// sqlReplicas returns a function opening store instances on the database
// dsn designates, each with its own pool, the schema migrated once.
func sqlReplicas(t *testing.T, driver, dsn string, dialect sqlstore.Dialect) func() oidcclient.TransactionStore {
	t.Helper()

	var once sync.Once

	return func() oidcclient.TransactionStore {
		s, err := sqlstore.New(openDB(t, driver, dsn), dialect)
		require.NoError(t, err)

		once.Do(func() { require.NoError(t, s.Migrate(t.Context())) })

		return s
	}
}

// postgresNamespace works in a new schema, selected through the
// search_path run-time parameter of a URL DSN.
func postgresNamespace(t *testing.T, dsn string) func() oidcclient.TransactionStore {
	t.Helper()

	admin := openDB(t, "pgx", dsn)
	schema := randomName("oidcclient_")

	_, err := admin.ExecContext(t.Context(), "CREATE SCHEMA "+schema)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = admin.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE") })

	u, err := url.Parse(dsn)
	require.NoError(t, err, "%s must be a URL (postgres://…)", envPostgresDSN)

	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()

	return sqlReplicas(t, "pgx", u.String(), sqlstore.Postgres)
}

// mysqlNamespace works in a new database.
func mysqlNamespace(t *testing.T, dsn string) func() oidcclient.TransactionStore {
	t.Helper()

	admin := openDB(t, "mysql", dsn)
	database := randomName("oidcclient_")

	_, err := admin.ExecContext(t.Context(), "CREATE DATABASE "+database)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = admin.ExecContext(context.Background(), "DROP DATABASE "+database) })

	cfg, err := mysqldriver.ParseDSN(dsn)
	require.NoError(t, err)

	cfg.DBName = database

	return sqlReplicas(t, "mysql", cfg.FormatDSN(), sqlstore.MySQL)
}

// redisNamespace works under a new key prefix; the keys expire with their
// transactions.
func redisNamespace(t *testing.T, addr string) func() oidcclient.TransactionStore {
	t.Helper()

	prefix := randomName("oidcclient-test-") + ":"

	return func() oidcclient.TransactionStore {
		rdb := redis.NewClient(&redis.Options{Addr: addr})
		t.Cleanup(func() { _ = rdb.Close() })

		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()

		require.NoError(t, rdb.Ping(ctx).Err(), "reaching redis")

		s, err := redisstore.New(rdb, redisstore.WithKeyPrefix(prefix))
		require.NoError(t, err)

		return s
	}
}

// forEachBackend runs test against every backend whose variable is set.
func forEachBackend(t *testing.T, test func(t *testing.T, replicas func() oidcclient.TransactionStore)) {
	t.Helper()

	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			dsn := os.Getenv(b.env)
			if dsn == "" {
				t.Skipf("set %s to run against a real %s (opt-in)", b.env, b.name)
			}

			test(t, b.namespace(t, dsn))
		})
	}
}

// TestRealBackendConformance runs the TransactionStore conformance suite
// — atomic consumption under 50 concurrent consumers included — on real
// PostgreSQL, MySQL and Redis servers, each case in a fresh namespace. The
// real-backend tests run one after the other, to bound the connections.
func TestRealBackendConformance(t *testing.T) {
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			dsn := os.Getenv(b.env)
			if dsn == "" {
				t.Skipf("set %s to run against a real %s (opt-in)", b.env, b.name)
			}

			storetest.RunConformance(t, func() oidcclient.TransactionStore { return b.namespace(t, dsn)() })
		})
	}
}

// hashHex returns hex(SHA-256(s)).
func hashHex(s string) string {
	sum := sha256.Sum256([]byte(s))

	return hex.EncodeToString(sum[:])
}

// replicaRaceRounds and replicaRaceConsumers size TestRealBackendReplicaRace.
const (
	replicaRaceRounds    = 20
	replicaRaceConsumers = 120
	replicaRaceReplicas  = 4
)

// TestRealBackendReplicaRace races, round after round, many consumers of
// one transaction spread over several store instances — separate pools,
// like the replicas of an application — a third of them presenting a
// wrong binding: exactly one consumer gets the transaction, the others
// fail with ErrTransactionNotFound or ErrBindingMismatch only.
func TestRealBackendReplicaRace(t *testing.T) {
	forEachBackend(t, func(t *testing.T, newReplica func() oidcclient.TransactionStore) {
		replicas := make([]oidcclient.TransactionStore, replicaRaceReplicas)
		for i := range replicas {
			replicas[i] = newReplica()
		}

		for round := range replicaRaceRounds {
			seed := randomName("round-")
			now := time.Unix(time.Now().Unix(), 0).UTC()
			tx := &oidcclient.Transaction{
				StateHash: hashHex("state-" + seed), BindingHash: hashHex("binding-" + seed),
				ConnectionID: "acme", Issuer: "https://idp.example.com", ClientID: "client-1",
				RedirectURI: "https://rp.example.com/oidc/acme/callback", ResponseMode: oidcclient.ResponseModeQuery,
				MaxAge: oidcclient.NoMaxAge, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute),
				Integrity: hashHex("integrity-" + seed),
			}
			require.NoError(t, replicas[round%replicaRaceReplicas].Save(t.Context(), tx))

			var (
				wg      sync.WaitGroup
				mu      sync.Mutex
				winners int
				start   = make(chan struct{})
				errs    = make([]error, replicaRaceConsumers)
			)

			for i := range replicaRaceConsumers {
				wg.Add(1)

				go func() {
					defer wg.Done()

					binding := tx.BindingHash
					if i%3 == 0 {
						binding = hashHex("wrong-" + seed)
					}

					<-start

					got, err := replicas[i%replicaRaceReplicas].Consume(context.Background(), tx.StateHash, binding, now)
					errs[i] = err

					if err == nil && got != nil {
						mu.Lock()
						winners++
						mu.Unlock()
					}
				}()
			}

			close(start)
			wg.Wait()

			require.Equal(t, 1, winners, "round %d: exactly one consumer gets the transaction", round)

			for _, err := range errs {
				if err != nil && !errors.Is(err, oidcclient.ErrTransactionNotFound) && !errors.Is(err, oidcclient.ErrBindingMismatch) {
					require.NoError(t, err, "round %d: a loser fails with not-found or binding mismatch only", round)
				}
			}
		}
	})
}
