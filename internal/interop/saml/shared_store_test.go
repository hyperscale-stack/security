// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlinterop_test

// Replay and atomicity across Service Provider instances sharing their
// persistence (issue #88, plan §5.3): three SP instances, each with its own
// handle (connection pool or client) on one backend, complete logins issued
// by crewjam's IdP. Rendezvous spies hold every contender at the store
// until all of them arrived, so the race really happens in the backend
// (plan review F5).
//
// Backends: a SQLite file in WAL mode and miniredis always; Redis,
// PostgreSQL and MySQL (with and without CLIENT_FOUND_ROWS) when their
// environment variables point at a disposable server (see compose.yaml):
//
//	SAMLSP_REDIS_ADDR=127.0.0.1:16379
//	SAMLSP_POSTGRES_DSN=postgres://samlsp:<password>@127.0.0.1:15432/samlsp?sslmode=disable
//	SAMLSP_MYSQL_DSN=root:<password>@tcp(127.0.0.1:13306)/

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	_ "github.com/go-sql-driver/mysql" // MySQL driver (opt-in backend)
	samlsp "github.com/hyperscale-stack/security/saml/sp"
	redisstore "github.com/hyperscale-stack/security/saml/sp/store/redis"
	sqlstore "github.com/hyperscale-stack/security/saml/sp/store/sql"
	"github.com/hyperscale-stack/security/saml/sp/storetest"
	_ "github.com/jackc/pgx/v5/stdlib" // PostgreSQL driver (opt-in backend)
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite" // pure-Go SQLite driver
)

// storeBackend opens namespaces of one persistence backend: each namespace
// is fresh and empty, and opens any number of independent instances.
type storeBackend struct {
	name string
	// namespace returns an opener of instances sharing one new namespace.
	namespace func(t *testing.T) func() samlsp.Storage
	// fastForward advances the backend's expiry clock (miniredis only).
	fastForward func(d time.Duration)
}

// unique returns a short random suffix for namespaces.
func unique() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)

	return hex.EncodeToString(b)
}

// sqlInstance opens one pool on dsn and migrates the schema (idempotent).
func sqlInstance(t *testing.T, driver, dsn string, d sqlstore.Dialect) samlsp.Storage {
	t.Helper()

	db, err := sql.Open(driver, dsn)
	require.NoError(t, err)
	db.SetMaxOpenConns(8)
	t.Cleanup(func() { _ = db.Close() })

	s, err := sqlstore.New(db, d)
	require.NoError(t, err)
	require.NoError(t, s.Migrate(context.Background()))

	return s
}

// storeBackends returns the backends of this run.
func storeBackends(t *testing.T) []storeBackend {
	t.Helper()

	mr := miniredis.RunT(t)

	backends := []storeBackend{
		{
			name: "sqlite-file",
			namespace: func(t *testing.T) func() samlsp.Storage {
				dsn := "file:" + filepath.Join(t.TempDir(), "samlsp.db") + "?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)"

				return func() samlsp.Storage { return sqlInstance(t, "sqlite", dsn, sqlstore.SQLite) }
			},
		},
		{
			name:        "miniredis",
			namespace:   redisNamespace(mr.Addr()),
			fastForward: mr.FastForward,
		},
	}

	if addr := os.Getenv("SAMLSP_REDIS_ADDR"); addr != "" {
		backends = append(backends, storeBackend{name: "redis", namespace: redisNamespace(addr)})
	}

	if dsn := os.Getenv("SAMLSP_POSTGRES_DSN"); dsn != "" {
		backends = append(backends, storeBackend{name: "postgres", namespace: postgresNamespace(dsn)})
	}

	if base := os.Getenv("SAMLSP_MYSQL_DSN"); base != "" {
		backends = append(backends,
			storeBackend{name: "mysql", namespace: mysqlNamespace(base, "")},
			storeBackend{name: "mysql-client-found-rows", namespace: mysqlNamespace(base, "clientFoundRows=true")},
		)
	}

	return backends
}

func redisNamespace(addr string) func(t *testing.T) func() samlsp.Storage {
	return func(t *testing.T) func() samlsp.Storage {
		prefix := "samlsp-it:" + unique() + ":"

		return func() samlsp.Storage {
			rdb := redis.NewClient(&redis.Options{Addr: addr, PoolSize: 32})
			t.Cleanup(func() { _ = rdb.Close() })

			s, err := redisstore.New(rdb, redisstore.WithKeyPrefix(prefix))
			require.NoError(t, err)

			return s
		}
	}
}

func postgresNamespace(dsn string) func(t *testing.T) func() samlsp.Storage {
	return func(t *testing.T) func() samlsp.Storage {
		schema := "samlsp_it_" + unique()

		admin, err := sql.Open("pgx", dsn)
		require.NoError(t, err)
		t.Cleanup(func() { _ = admin.Close() })

		_, err = admin.Exec("CREATE SCHEMA " + schema)
		require.NoError(t, err)
		t.Cleanup(func() { _, _ = admin.Exec("DROP SCHEMA " + schema + " CASCADE") })

		sep := "?"
		if strings.Contains(dsn, "?") {
			sep = "&"
		}

		return func() samlsp.Storage {
			return sqlInstance(t, "pgx", dsn+sep+"search_path="+schema, sqlstore.Postgres)
		}
	}
}

func mysqlNamespace(base, params string) func(t *testing.T) func() samlsp.Storage {
	return func(t *testing.T) func() samlsp.Storage {
		db := "samlsp_it_" + unique()

		admin, err := sql.Open("mysql", base)
		require.NoError(t, err)
		t.Cleanup(func() { _ = admin.Close() })

		_, err = admin.Exec("CREATE DATABASE " + db)
		require.NoError(t, err)
		t.Cleanup(func() { _, _ = admin.Exec("DROP DATABASE " + db) })

		dsn := base + db
		if params != "" {
			dsn += "?" + params
		}

		return func() samlsp.Storage { return sqlInstance(t, "mysql", dsn, sqlstore.MySQL) }
	}
}

// rendezvous releases its waiters together once n arrived (or after a
// timeout, which the test then reports).
type rendezvous struct {
	n       int
	mu      sync.Mutex
	arrived int
	release chan struct{}
}

func newRendezvous(n int) *rendezvous { return &rendezvous{n: n, release: make(chan struct{})} }

func (r *rendezvous) wait() {
	r.mu.Lock()
	r.arrived++

	if r.arrived == r.n {
		close(r.release)
	}
	r.mu.Unlock()

	select {
	case <-r.release:
	case <-time.After(15 * time.Second):
	}
}

// met reports whether every contender reached the rendezvous.
func (r *rendezvous) met() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.arrived == r.n
}

// raceStore holds ConsumeTransaction and MarkAssertionUsed at the current
// rendezvous, if any, before reaching the backend.
type raceStore struct {
	samlsp.Storage

	consume atomic.Pointer[rendezvous]
	mark    atomic.Pointer[rendezvous]
}

func (s *raceStore) ConsumeTransaction(ctx context.Context, id, bindingHash string) error {
	if r := s.consume.Load(); r != nil {
		r.wait()
	}

	return s.Storage.ConsumeTransaction(ctx, id, bindingHash)
}

func (s *raceStore) MarkAssertionUsed(ctx context.Context, key string, expiresAt time.Time) error {
	if r := s.mark.Load(); r != nil {
		r.wait()
	}

	return s.Storage.MarkAssertionUsed(ctx, key, expiresAt)
}

// cluster is three SP instances on one backend namespace, federated with
// one crewjam IdP under two connections (acme, globex).
type cluster struct {
	idp     *identityProvider
	sp      *serviceProvider
	stores  []*raceStore
	backend storeBackend
}

func newCluster(t *testing.T, b storeBackend) *cluster {
	t.Helper()

	open := b.namespace(t)
	c := &cluster{backend: b}

	for range 3 {
		c.stores = append(c.stores, &raceStore{Storage: open()})
	}

	c.idp = newIdentityProvider(t, newKey(t, "idp"), rsaSHA256)
	c.sp = newServiceProvider(t, spOptions{instances: 3, storage: func(i int) samlsp.Storage { return c.stores[i] }})

	for _, conn := range []string{"acme", "globex"} {
		c.sp.addConnection(t, conn, c.idp.metadata(t), nil)
		c.idp.registerSP(t, c.sp.metadata(t, conn))
	}

	return c
}

// login signs in a new browser at acme and returns its POST form and its
// binding cookie.
func (c *cluster) login(t *testing.T) (*browser, postForm, string) {
	t.Helper()

	b := newBrowser(t, c.sp.srv)
	_, form := b.mustSignIn(t, c.sp, "acme")

	return b, form, bindingCookie(t, b, c.sp)
}

// bindingCookie returns the browser-binding cookie of b at sp.
func bindingCookie(t *testing.T, b *browser, sp *serviceProvider) string {
	t.Helper()

	u, err := url.Parse(sp.srv.URL)
	require.NoError(t, err)

	for _, ck := range b.client.Jar.Cookies(u) {
		if ck.Name == samlsp.DefaultCookieName {
			return ck.Value
		}
	}

	t.Fatal("no browser-binding cookie")

	return ""
}

// acsRequest is the browser's POST of form to the ACS of conn.
func acsRequest(t *testing.T, base string, conn string, form postForm, cookie string) *http.Request {
	t.Helper()

	body := url.Values{"SAMLResponse": {form.samlResponse}, "RelayState": {form.relayState}}.Encode()
	req := httptest.NewRequest(http.MethodPost, base+"/saml/"+conn+"/acs", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: samlsp.DefaultCookieName, Value: cookie})

	return req
}

// complete posts form on instance i.
func (c *cluster) complete(t *testing.T, i int, conn string, form postForm, cookie string) error {
	t.Helper()

	_, err := c.sp.instances[i%len(c.sp.instances)].CompleteLogin(context.Background(),
		acsRequest(t, c.sp.srv.URL, conn, form, cookie), conn)

	return err
}

// transactionConsumed reports whether the transaction of form is consumed.
func (c *cluster) transactionConsumed(t *testing.T, form postForm) bool {
	t.Helper()

	sum := sha256.Sum256([]byte("samlsp-v1/transaction\x00acme\x00" + form.relayState))
	_, err := c.stores[0].LookupTransaction(context.Background(), hex.EncodeToString(sum[:]))

	return errors.Is(err, samlsp.ErrTransactionConsumed)
}

// raceRounds is the number of rounds of each race (F5: at least 10).
func raceRounds(t *testing.T) int {
	t.Helper()

	if v := os.Getenv("SAMLSP_RACE_ROUNDS"); v != "" {
		n, err := strconv.Atoi(v)
		require.NoError(t, err)

		return n
	}

	return 10
}

// contenders is the number of concurrent posts of each race.
const contenders = 16

// race runs fn on contenders goroutines released together.
func race(fn func(i int) error) []error {
	var wg sync.WaitGroup

	errs := make([]error, contenders)
	start := make(chan struct{})

	for i := range contenders {
		wg.Go(func() {
			<-start

			errs[i] = fn(i)
		})
	}

	close(start)
	wg.Wait()

	return errs
}

// tally counts successes, rejections matching want, and anything else.
func tally(errs []error, want error) (ok, matched int, other []error) {
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, want):
			matched++
		default:
			other = append(other, err)
		}
	}

	return ok, matched, other
}

func TestSharedStoreRaces(t *testing.T) {
	t.Parallel()

	for _, b := range storeBackends(t) {
		t.Run(b.name, func(t *testing.T) {
			c := newCluster(t, b)
			rounds := raceRounds(t)

			t.Run("S1 one response posted 16 times across instances", func(t *testing.T) {
				for round := range rounds {
					_, form, cookie := c.login(t)

					rv := newRendezvous(contenders)
					for _, s := range c.stores {
						s.consume.Store(rv)
					}

					errs := race(func(i int) error { return c.complete(t, i, "acme", form, cookie) })

					for _, s := range c.stores {
						s.consume.Store(nil)
					}

					ok, consumed, other := tally(errs, samlsp.ErrTransactionConsumed)
					require.True(t, rv.met(), "round %d: every contender reached the store", round)
					require.Empty(t, other, "round %d: unexpected outcomes", round)
					require.Equal(t, 1, ok, "round %d: exactly one consumption", round)
					require.Equal(t, contenders-1, consumed, "round %d", round)
				}
			})

			t.Run("S2 one assertion ID in 16 transactions", func(t *testing.T) {
				for round := range rounds {
					c.idp.pinAssertionID(fmt.Sprintf("_pinned-%s-%d", unique(), round))

					forms := make([]postForm, contenders)
					cookies := make([]string, contenders)

					for i := range contenders {
						_, forms[i], cookies[i] = c.login(t)
					}

					c.idp.pinAssertionID("")

					rv := newRendezvous(contenders)
					for _, s := range c.stores {
						s.mark.Store(rv)
					}

					errs := race(func(i int) error { return c.complete(t, i, "acme", forms[i], cookies[i]) })

					for _, s := range c.stores {
						s.mark.Store(nil)
					}

					ok, replayed, other := tally(errs, samlsp.ErrAssertionReplayed)
					require.True(t, rv.met(), "round %d: every contender reached the replay cache", round)
					require.Empty(t, other, "round %d: unexpected outcomes", round)
					require.Equal(t, 1, ok, "round %d: exactly one login with the assertion", round)
					require.Equal(t, contenders-1, replayed, "round %d", round)

					for i := range contenders {
						require.True(t, c.transactionConsumed(t, forms[i]), "round %d: every transaction ends consumed (fail closed)", round)
					}
				}
			})

			t.Run("S3 replay after success on another instance", func(t *testing.T) {
				_, form, cookie := c.login(t)
				require.NoError(t, c.complete(t, 0, "acme", form, cookie))
				require.ErrorIs(t, c.complete(t, 1, "acme", form, cookie), samlsp.ErrTransactionConsumed)

				if b.fastForward != nil {
					// The consumed transaction expires with its TTL; the replay
					// then finds nothing and still fails.
					b.fastForward(samlsp.DefaultTransactionTTL + time.Minute)
					require.ErrorIs(t, c.complete(t, 2, "acme", form, cookie), samlsp.ErrTransactionNotFound)
				}
			})

			t.Run("S4 a transaction posted to another connection", func(t *testing.T) {
				_, form, cookie := c.login(t)
				require.ErrorIs(t, c.complete(t, 1, "globex", form, cookie), samlsp.ErrTransactionNotFound)
				require.NoError(t, c.complete(t, 2, "acme", form, cookie), "nothing was burnt")
			})

			t.Run("S5 login started on one instance completes on another", func(t *testing.T) {
				served := int(c.sp.next.Load() % 3)
				_, form, cookie := c.login(t)
				require.NoError(t, c.complete(t, served+1, "acme", form, cookie))
			})

			t.Run("S6 a consumed response replayed through a new transaction", func(t *testing.T) {
				b, form, cookie := c.login(t)
				require.NoError(t, c.complete(t, 0, "acme", form, cookie))

				_, next := b.mustSignIn(t, c.sp, "acme")
				form.relayState = next.relayState
				require.ErrorIs(t, c.complete(t, 1, "acme", form, cookie), samlsp.ErrInResponseToMismatch)
			})
		})
	}
}

// TestSharedStoreConformance runs the storage contract on every backend,
// each case on a fresh namespace.
func TestSharedStoreConformance(t *testing.T) {
	t.Parallel()

	for _, b := range storeBackends(t) {
		t.Run(b.name, func(t *testing.T) {
			storetest.RunConformance(t, func() samlsp.Storage { return b.namespace(t)() })
		})
	}
}
