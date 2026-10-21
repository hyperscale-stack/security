// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstores_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/hyperscale-stack/security/oauth2"
	oauth2sql "github.com/hyperscale-stack/security/oauth2/store/sql"
	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	oidcsql "github.com/hyperscale-stack/security/oidc/client/store/sql"
	samlsp "github.com/hyperscale-stack/security/saml/sp"
	samlsql "github.com/hyperscale-stack/security/saml/sp/store/sql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// allServers are every backend the purges run on.
var allServers = []backend{sqliteFile, postgres, mysql80, mysql84, mariadb}

// expiringPair returns a pair of family whose tokens expire at expiresAt.
func expiringPair(name, family string, expiresAt time.Time) *oauth2.TokenPair {
	pair := tokenPair(name, family)
	pair.Access.ExpiresAt, pair.Refresh.ExpiresAt = expiresAt, expiresAt

	return pair
}

// expiringCode returns a code expiring at expiresAt.
func expiringCode(hash string, expiresAt time.Time) *oauth2.AuthorizationCode {
	return &oauth2.AuthorizationCode{
		CodeHash: hash, ClientID: "client-1", Subject: "alice", RedirectURI: "https://app.example/cb", Scope: "read",
		IssuedAt: expiresAt.Add(-time.Minute), ExpiresAt: expiresAt,
	}
}

// tableRows returns the number of rows of table.
func tableRows(t *testing.T, db *sql.DB, table string) int {
	t.Helper()

	var n int
	require.NoError(t, db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM "+table).Scan(&n))

	return n
}

// TestOAuth2PurgeExpired runs PurgeExpired on every server: the rows
// expired before now go — two codes, three access tokens, two refresh
// tokens, one family — and the rows expiring at now, the live ones and the
// record of a revoked family within its retention stay; the live pair is
// still usable, the revoked family still refuses issuance.
func TestOAuth2PurgeExpired(t *testing.T) {
	for _, b := range allServers {
		t.Run(b.name, func(t *testing.T) {
			b.server(t)

			ctx := t.Context()
			driver, dsn := b.namespace(t)
			db := open(t, driver, dsn, 4)

			s, err := oauth2sql.New(db, oauth2Dialect(b.engine))
			require.NoError(t, err)
			require.NoError(t, s.Migrate(ctx))

			now := time.Unix(time.Now().Unix(), 0)
			past := now.Add(-time.Hour)

			for _, code := range []*oauth2.AuthorizationCode{
				expiringCode("code-expired", past), expiringCode("code-consumed", past),
				expiringCode("code-boundary", now), expiringCode("code-live", now.Add(time.Hour)),
			} {
				require.NoError(t, s.SaveAuthorizationCode(ctx, code))
			}

			_, err = s.ConsumeAuthorizationCode(ctx, "code-consumed")
			require.NoError(t, err)

			cc := expiringPair("purge-cc", "", past)
			cc.Refresh = nil
			live := expiringPair("purge-live", "fam-purge-live", now.Add(time.Hour))

			for _, pair := range []*oauth2.TokenPair{
				expiringPair("purge-expired", "fam-purge-expired", past), cc, live,
				expiringPair("purge-revoked", "fam-purge-revoked", past),
				expiringPair("purge-boundary", "fam-purge-boundary", now),
			} {
				require.NoError(t, s.SaveTokenPair(ctx, pair))
			}

			require.NoError(t, s.RevokeRefreshFamily(ctx, "fam-purge-revoked"))

			n, err := s.PurgeExpired(ctx, now)
			require.NoError(t, err)
			assert.Equal(t, int64(8), n)

			for table, rows := range map[string]int{
				"oauth2_auth_codes": 2, "oauth2_access_tokens": 2, "oauth2_refresh_tokens": 2, "oauth2_token_families": 3,
			} {
				assert.Equal(t, rows, tableRows(t, db, table), table)
			}

			_, err = s.LookupAccessToken(ctx, live.Access.TokenHash)
			require.NoError(t, err)
			require.ErrorIs(t, s.SaveTokenPair(ctx, expiringPair("purge-again", "fam-purge-revoked", now.Add(time.Hour))),
				oauth2.ErrTokenFamilyRevoked)

			n, err = s.PurgeExpired(ctx, now)
			require.NoError(t, err)
			assert.Zero(t, n)
		})
	}
}

// TestSAMLPurgeExpired runs the SAML store's PurgeExpired on every server:
// the transaction and the replay mark expired before now go, those
// expiring at now and the live ones stay.
func TestSAMLPurgeExpired(t *testing.T) {
	for _, b := range allServers {
		t.Run(b.name, func(t *testing.T) {
			b.server(t)

			ctx := t.Context()
			driver, dsn := b.namespace(t)
			db := open(t, driver, dsn, 2)

			s, err := samlsql.New(db, samlDialect(b.engine))
			require.NoError(t, err)
			require.NoError(t, s.Migrate(ctx))

			now := time.Unix(time.Now().Unix(), 0)

			for label, expires := range map[string]time.Time{
				"expired": now.Add(-time.Hour), "boundary": now, "live": now.Add(time.Hour),
			} {
				require.NoError(t, s.SaveTransaction(ctx, &samlsp.TransactionRecord{
					ID: sha256Hex("tx/" + label), BindingHash: sha256Hex("b/" + label), Payload: `{"v":1}`,
					ExpiresAt: expires, Integrity: sha256Hex("i/" + label),
				}))
				require.NoError(t, s.MarkAssertionUsed(ctx, sha256Hex("as/"+label), expires))
			}

			n, err := s.PurgeExpired(ctx, now)
			require.NoError(t, err)
			assert.Equal(t, int64(2), n)
			assert.Equal(t, 2, tableRows(t, db, "samlsp_transactions"))
			assert.Equal(t, 2, tableRows(t, db, "samlsp_used_assertions"))
		})
	}
}

// TestOAuth2PurgeKeepsAFamilyExtendedMeanwhile: a revocation extends the
// retention of an expired family while a purge runs. The purge waits for
// the family's row, then re-checks its expiry on the committed row and
// keeps it: a revoked family deleted before its new expiry would be
// recorded active again by the next issuance into it. (On PostgreSQL the
// batch picks its rows in a subquery, which a wait does not re-run: the
// outer DELETE repeats the expiry.)
func TestOAuth2PurgeKeepsAFamilyExtendedMeanwhile(t *testing.T) {
	for _, b := range lockingServers {
		t.Run(b.name, func(t *testing.T) {
			b.server(t)

			store, db, admin := lockingStore(t, b)
			now := time.Unix(time.Now().Unix(), 0)

			require.NoError(t, store.SaveTokenPair(t.Context(), expiringPair("extended", "fam-extended", now.Add(-time.Hour))))

			holder := holdLocks(t, db, b.engine, stmt{
				`UPDATE oauth2_token_families SET revoked_at = ?, expires_at = ? WHERE family_id = ?`,
				[]any{now.Unix(), now.Add(oauth2.FamilyRevocationRetention).Unix(), "fam-extended"},
			})

			done := make(chan int64, 1)

			go func() {
				n, err := store.PurgeExpired(context.Background(), now)
				assert.NoError(t, err)

				done <- n
			}()

			holder.waitForWaiter(admin)
			holder.commit()

			assert.Equal(t, int64(2), <-done, "the expired tokens go, the family stays")
			require.Equal(t, 1, countRows(t, db, b.engine, "oauth2_token_families", "family_id", "fam-extended"))
			require.ErrorIs(t, store.SaveTokenPair(t.Context(), expiringPair("extended-again", "fam-extended", now.Add(time.Hour))),
				oauth2.ErrTokenFamilyRevoked)
		})
	}
}

// purgeTarget is a store whose purge TestPurgeDoesNotBlockInserts runs: it
// stores records expired under keys sorting around a live one, then must
// insert a record under a key sorting before all of them while a purge
// waits for the live one's row.
type purgeTarget struct {
	name string
	// table and column hold the records and their keys.
	table, column string
	// setup migrates the store on db and returns its purge and its
	// insert, the latter bound to the pool insertDB.
	setup func(t *testing.T, db, insertDB *sql.DB) (purge func(now time.Time) error, insert func(key string) error)
	// save stores a record under key, expiring at expiresAt.
	save func(t *testing.T, db *sql.DB, key string, expiresAt time.Time)
}

// hexKey is a 64-hex-digit store key starting with digit, so that keys
// sort by it.
func hexKey(digit string) string { return digit + strings.Repeat("0", 63) }

var purgeTargets = []purgeTarget{
	{
		name: "oauth2", table: "oauth2_auth_codes", column: "code_hash",
		setup: func(t *testing.T, db, insertDB *sql.DB) (func(time.Time) error, func(string) error) {
			s, err := oauth2sql.New(db, oauth2sql.MySQL)
			require.NoError(t, err)
			require.NoError(t, s.Migrate(t.Context()))

			inserter, err := oauth2sql.New(insertDB, oauth2sql.MySQL)
			require.NoError(t, err)

			return func(now time.Time) error {
					_, err := s.PurgeExpired(context.Background(), now)

					return err
				}, func(key string) error {
					return inserter.SaveAuthorizationCode(context.Background(), expiringCode(key, time.Now().Add(time.Hour)))
				}
		},
		save: func(t *testing.T, db *sql.DB, key string, expiresAt time.Time) {
			s, err := oauth2sql.New(db, oauth2sql.MySQL)
			require.NoError(t, err)
			require.NoError(t, s.SaveAuthorizationCode(t.Context(), expiringCode(key, expiresAt)))
		},
	},
	{
		name: "oidc", table: "oidc_client_transactions", column: "state_hash",
		setup: func(t *testing.T, db, insertDB *sql.DB) (func(time.Time) error, func(string) error) {
			s, err := oidcsql.New(db, oidcsql.MySQL)
			require.NoError(t, err)
			require.NoError(t, s.Migrate(t.Context()))

			inserter, err := oidcsql.New(insertDB, oidcsql.MySQL)
			require.NoError(t, err)

			return func(now time.Time) error {
					_, err := s.PurgeExpired(context.Background(), now)

					return err
				}, func(key string) error {
					return inserter.Save(context.Background(), oidcTransaction(key, time.Now().Add(time.Hour)))
				}
		},
		save: func(t *testing.T, db *sql.DB, key string, expiresAt time.Time) {
			s, err := oidcsql.New(db, oidcsql.MySQL)
			require.NoError(t, err)
			require.NoError(t, s.Save(t.Context(), oidcTransaction(key, expiresAt)))
		},
	},
	{
		name: "saml", table: "samlsp_used_assertions", column: "assertion_key",
		setup: func(t *testing.T, db, insertDB *sql.DB) (func(time.Time) error, func(string) error) {
			s, err := samlsql.New(db, samlsql.MySQL)
			require.NoError(t, err)
			require.NoError(t, s.Migrate(t.Context()))

			inserter, err := samlsql.New(insertDB, samlsql.MySQL)
			require.NoError(t, err)

			return func(now time.Time) error {
					_, err := s.PurgeExpired(context.Background(), now)

					return err
				}, func(key string) error {
					return inserter.MarkAssertionUsed(context.Background(), key,
						time.Unix(time.Now().Add(time.Hour).Unix(), 0))
				}
		},
		save: func(t *testing.T, db *sql.DB, key string, expiresAt time.Time) {
			s, err := samlsql.New(db, samlsql.MySQL)
			require.NoError(t, err)
			require.NoError(t, s.MarkAssertionUsed(t.Context(), key, expiresAt))
		},
	},
}

// oidcTransaction returns a transaction stored under stateHash, expiring
// at expiresAt.
func oidcTransaction(stateHash string, expiresAt time.Time) *oidcclient.Transaction {
	expires := time.Unix(expiresAt.Unix(), 0).UTC()

	return &oidcclient.Transaction{
		StateHash: stateHash, BindingHash: sha256Hex("binding-" + stateHash),
		ConnectionID: "acme", Issuer: "https://idp.example.com", ClientID: "client-1",
		RedirectURI: "https://rp.example.com/oidc/acme/callback", ResponseMode: oidcclient.ResponseModeQuery,
		MaxAge: oidcclient.NoMaxAge, CreatedAt: expires.Add(-time.Hour), ExpiresAt: expires,
		Integrity: sha256Hex("integrity-" + stateHash),
	}
}

// TestPurgeDoesNotBlockInserts: on MySQL, a purge — which scans its table
// when expires_at has no index, as MySQL creates none — waits for a live
// row another transaction holds. Meanwhile a new record must still be
// inserted, under a key sorting before every scanned one: at READ
// COMMITTED the purge locks only the rows it deletes, where at the
// server's REPEATABLE READ it would also lock the gaps it scanned, and the
// insert would time out (innodb_lock_wait_timeout, here 1 s).
func TestPurgeDoesNotBlockInserts(t *testing.T) {
	for _, b := range mysqlServers {
		t.Run(b.name, func(t *testing.T) {
			b.server(t)

			for _, target := range purgeTargets {
				t.Run(target.name, func(t *testing.T) {
					driver, dsn := b.namespace(t)
					db := open(t, driver, dsn, 4)
					admin := open(t, driver, dsn, 1)

					cfg, err := mysqldriver.ParseDSN(dsn)
					require.NoError(t, err)

					cfg.Params = map[string]string{"innodb_lock_wait_timeout": "1"}
					insertDB := open(t, driver, cfg.FormatDSN(), 1)

					purge, insert := target.setup(t, db, insertDB)

					now := time.Unix(time.Now().Unix(), 0)
					target.save(t, db, hexKey("2"), now.Add(-time.Hour))
					target.save(t, db, hexKey("8"), now.Add(time.Hour))
					target.save(t, db, hexKey("e"), now.Add(-time.Hour))

					holder := holdLocks(t, db, engineMySQL, stmt{
						"SELECT " + target.column + " FROM " + target.table + " WHERE " + target.column + " = ? FOR UPDATE",
						[]any{hexKey("8")},
					})

					done := make(chan error, 1)

					go func() { done <- purge(now) }()

					holder.waitForWaiter(admin)
					require.NoError(t, insert(hexKey("0")), "an insert while the purge waits")

					holder.commit()
					require.NoError(t, <-done)
					require.Equal(t, 2, tableRows(t, db, target.table), "the live and the new record stay")
				})
			}
		})
	}
}
