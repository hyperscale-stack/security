// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstores_test

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hyperscale-stack/security/oauth2"
	oauth2sql "github.com/hyperscale-stack/security/oauth2/store/sql"
	"github.com/hyperscale-stack/security/oauth2/storetest"
	"github.com/stretchr/testify/require"
)

// mysqlServers are the MySQL-family servers the deployment checks run on.
var mysqlServers = []backend{mysql80, mysql84, mariadb}

// withParams returns b whose namespaces set the given system variables on
// every connection, under a name of its own.
func withParams(b backend, suffix string, params map[string]string) backend {
	b.name += "-" + suffix
	b.params = params

	return b
}

// myisamDefault makes MyISAM the storage engine of every CREATE TABLE that
// names none: a server started with --default-storage-engine=MyISAM.
var myisamDefault = map[string]string{"default_storage_engine": "'MyISAM'"}

// tableStatus returns the storage engine and collation of table in the
// namespace db works in, "" for a missing table.
func tableStatus(t *testing.T, db *sql.DB, table string) (engine, collation string) {
	t.Helper()

	err := db.QueryRowContext(t.Context(), `SELECT ENGINE, TABLE_COLLATION FROM information_schema.TABLES
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?`, table).Scan(&engine, &collation)
	if err == sql.ErrNoRows {
		return "", ""
	}

	require.NoError(t, err)

	return engine, collation
}

// requireInnoDB asserts that every table of s is InnoDB, in utf8mb4.
func requireInnoDB(t *testing.T, db *sql.DB, s sqlStore) {
	t.Helper()

	for _, table := range s.tables {
		engine, collation := tableStatus(t, db, table)
		require.Equal(t, "InnoDB", engine, "engine of %s", table)
		require.True(t, strings.HasPrefix(collation, "utf8mb4"), "collation of %s: %s", table, collation)
	}
}

// TestMySQLMigrateCreatesInnoDBTables runs Migrate on servers whose
// default storage engine is MyISAM: the DDL names InnoDB and utf8mb4, so
// every table is created InnoDB — the engine whose transactions and row
// locks the stores rest on — and Migrate's own check passes.
func TestMySQLMigrateCreatesInnoDBTables(t *testing.T) {
	for _, base := range mysqlServers {
		b := withParams(base, "myisam-default", myisamDefault)

		t.Run(b.name, func(t *testing.T) {
			b.server(t)

			for _, s := range sqlStores {
				t.Run(s.name, func(t *testing.T) {
					driver, dsn := b.namespace(t)
					db := open(t, driver, dsn, 4)

					require.NoError(t, s.migrate(t.Context(), db, engineMySQL))
					requireInnoDB(t, db, s)
					s.use(t, db, engineMySQL)
				})
			}
		})
	}
}

// engineSection is the heading of the MIGRATION.md section whose SQL
// blocks — the preflight query, the conversion to InnoDB, the conversion
// to utf8mb4 — TestMySQLCheckDeploymentRefusesMyISAM runs.
const engineSection = "### SQL stores: MySQL tables are InnoDB, checked at boot"

// sectionBlocks returns the SQL blocks of the MIGRATION.md section
// heading, each as its statements.
func sectionBlocks(t *testing.T, heading string) [][]string {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "MIGRATION.md"))
	require.NoError(t, err)

	doc := string(raw)
	start := strings.Index(doc, "\n"+heading+"\n")
	require.GreaterOrEqual(t, start, 0, "MIGRATION.md has no section %q", heading)

	return sqlBlocks(t, doc[start+1:], heading)
}

// TestMySQLCheckDeploymentRefusesMyISAM: tables a MyISAM-default server
// created before the DDL named an engine stay MyISAM — CREATE TABLE IF NOT
// EXISTS leaves them — so CheckDeployment, and Migrate which ends with it,
// refuse them, naming each table. The statements MIGRATION.md gives
// convert them; then both pass and the stores work, the oauth2 one passing
// its conformance suite.
func TestMySQLCheckDeploymentRefusesMyISAM(t *testing.T) {
	blocks := sectionBlocks(t, engineSection)
	require.Len(t, blocks, 3, "the preflight, the engine conversion and the character-set conversion")

	for _, base := range mysqlServers {
		b := withParams(base, "myisam", myisamDefault)

		t.Run(b.name, func(t *testing.T) {
			b.server(t)

			driver, dsn := b.namespace(t)
			db := open(t, driver, dsn, 4)
			createMyISAM(t, db)

			for _, s := range sqlStores {
				err := s.check(t.Context(), db, engineMySQL)
				require.ErrorIs(t, err, s.requirement, "CheckDeployment of %s", s.name)

				for _, table := range s.tables {
					require.Contains(t, err.Error(), "table "+table+" uses the MyISAM engine, not InnoDB")
				}

				require.ErrorIs(t, s.migrate(t.Context(), db, engineMySQL), s.requirement, "Migrate of %s", s.name)
			}

			execAll(t, db, blocks[0]...)
			execAll(t, db, blocks[1]...)
			execAll(t, db, blocks[2]...)

			for _, s := range sqlStores {
				require.NoError(t, s.check(t.Context(), db, engineMySQL), "CheckDeployment of %s", s.name)
				require.NoError(t, s.migrate(t.Context(), db, engineMySQL), "Migrate of %s", s.name)
				requireInnoDB(t, db, s)
				s.use(t, db, engineMySQL)
			}

			storetest.RunConformance(t, func() oauth2.Storage {
				store, err := oauth2sql.New(db, oauth2sql.MySQL)
				require.NoError(t, err)

				return store
			})
		})
	}
}

// createMyISAM creates the tables of every store as MyISAM tables.
func createMyISAM(t *testing.T, db *sql.DB) {
	t.Helper()

	for _, s := range sqlStores {
		for _, stmt := range s.schema(engineMySQL) {
			execAll(t, db, strings.Replace(stmt, "ENGINE=InnoDB", "ENGINE=MyISAM", 1))
		}

		for _, table := range s.tables {
			engine, _ := tableStatus(t, db, table)
			require.Equal(t, "MyISAM", engine, "engine of %s", table)
		}
	}
}

// TestMySQLCheckDeploymentRefusesNonStrictSQLMode: without a strict
// sql_mode, MySQL truncates an over-long subject or client ID instead of
// refusing it; the oauth2 store, which carries no integrity check of its
// own, refuses such a session. The OIDC and SAML records are bounded and
// MAC-protected: they have no sql_mode requirement.
func TestMySQLCheckDeploymentRefusesNonStrictSQLMode(t *testing.T) {
	for _, base := range mysqlServers {
		for _, mode := range []string{"''", "'NO_ENGINE_SUBSTITUTION'", "'ANSI_QUOTES,NO_ZERO_DATE'"} {
			b := withParams(base, "sql-mode-"+strings.Trim(mode, "'"), map[string]string{"sql_mode": mode})

			t.Run(b.name, func(t *testing.T) {
				b.server(t)

				driver, dsn := b.namespace(t)
				db := open(t, driver, dsn, 2)

				for _, s := range sqlStores {
					err := s.migrate(t.Context(), db, engineMySQL)
					if s.name != "oauth2" {
						require.NoError(t, err, "Migrate of %s", s.name)

						continue
					}

					require.ErrorIs(t, err, s.requirement)
					require.Contains(t, err.Error(), "sql_mode")
					require.ErrorIs(t, s.check(t.Context(), db, engineMySQL), s.requirement)
				}
			})
		}

		for _, mode := range []string{"'TRADITIONAL'", "'STRICT_ALL_TABLES'", "'STRICT_TRANS_TABLES'"} {
			b := withParams(base, "sql-mode-"+strings.Trim(mode, "'"), map[string]string{"sql_mode": mode})

			t.Run(b.name, func(t *testing.T) {
				b.server(t)

				driver, dsn := b.namespace(t)
				db := open(t, driver, dsn, 2)

				for _, s := range sqlStores {
					require.NoError(t, s.migrate(t.Context(), db, engineMySQL), "Migrate of %s", s.name)
				}
			})
		}
	}
}

// TestMySQLCheckDeploymentRefusesLegacyKeys: an oauth2 database created
// before its key columns were binary compares keys under a collation that
// may ignore case, accents or trailing spaces; CheckDeployment names each
// such column, and passes once MIGRATION.md's upgrade is applied.
func TestMySQLCheckDeploymentRefusesLegacyKeys(t *testing.T) {
	blocks := upgradeBlocks(t)
	upgrade := append(blocks[1], blocks[2]...)

	for _, b := range mysqlServers {
		t.Run(b.name, func(t *testing.T) {
			b.server(t)

			driver, dsn := b.namespace(t)
			db := open(t, driver, dsn, 2)
			execAll(t, db, legacyMySQLSchema...)

			s := sqlStores[0]
			err := s.check(t.Context(), db, engineMySQL)
			require.ErrorIs(t, err, oauth2sql.ErrDeploymentRequirement)

			for _, column := range []string{
				"oauth2_auth_codes.code_hash", "oauth2_access_tokens.token_hash", "oauth2_access_tokens.family_id",
				"oauth2_refresh_tokens.token_hash", "oauth2_refresh_tokens.family_id", "oauth2_token_families.family_id",
			} {
				require.Contains(t, err.Error(), "column "+column+" is varchar, not varbinary")
			}

			execAll(t, db, upgrade...)
			require.NoError(t, s.check(t.Context(), db, engineMySQL))
		})
	}
}

// TestMySQLCheckDeploymentReportsMissingTables: a table the database does
// not hold — a migration not applied, another database selected — is
// reported, never taken for a compliant one.
func TestMySQLCheckDeploymentReportsMissingTables(t *testing.T) {
	for _, b := range mysqlServers {
		t.Run(b.name, func(t *testing.T) {
			b.server(t)

			driver, dsn := b.namespace(t)
			db := open(t, driver, dsn, 2)

			for _, s := range sqlStores {
				require.NoError(t, s.migrate(t.Context(), db, engineMySQL))

				missing := s.tables[len(s.tables)-1]
				execAll(t, db, "DROP TABLE "+missing)

				err := s.check(t.Context(), db, engineMySQL)
				require.ErrorIs(t, err, s.requirement, "CheckDeployment of %s", s.name)
				require.Contains(t, err.Error(), "table "+missing+" not found")
			}
		})
	}
}
