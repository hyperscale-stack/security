// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore

import (
	"context"
	"fmt"
)

// Schema returns the DDL statements that create the four tables backing
// the store: authorization codes — a consumed one keeps its row, flagged
// consumed, until an operator deletes it — access tokens, refresh tokens,
// and the token families — one record per family, active (revoked_at = 0)
// or revoked (revoked_at = Unix second of the first revocation), retained
// until expires_at. Timestamps are stored as BIGINT Unix seconds to dodge the
// TIMESTAMP / DATETIME portability minefield between engines, and flags as
// SMALLINT 0/1 since PostgreSQL has no implicit integer/boolean cast. Token
// / code raw values are NEVER stored — only their hashes.
//
// The DDL sticks to the subset every supported engine accepts, so it is
// the same for every [Dialect]: the argument is accepted for API stability
// and ignored. The issuer and extension_data columns of codes and tokens —
// the realm a grant is bound to and the opaque state an oauth2.Extension
// recorded for it — are nullable TEXT, the only form every engine accepts
// in an ALTER TABLE … ADD COLUMN on a populated table, so a database
// created before them is upgraded with the statements MIGRATION.md lists
// and ends up with the same columns as a new one. The store writes an
// empty value as the empty string and reads NULL as the empty string. The
// redirect_uri_omitted flag of codes is a SMALLINT NOT NULL DEFAULT 0, and
// the family_issued_at of refresh tokens a BIGINT NOT NULL DEFAULT 0 (0: no
// recorded family start), which every engine also accepts on a populated
// table: a row written before them reads 0.
//
// The statements are idempotent (CREATE TABLE IF NOT EXISTS). Production
// deployments typically run them through a migration tool rather than via
// [Store.Migrate], but Migrate is offered for tests and small setups.
func Schema(_ Dialect) []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS oauth2_auth_codes (
			code_hash             VARCHAR(128) PRIMARY KEY,
			client_id             VARCHAR(255) NOT NULL,
			subject               VARCHAR(255) NOT NULL,
			redirect_uri          TEXT         NOT NULL,
			scope                 TEXT         NOT NULL,
			code_challenge        TEXT         NOT NULL,
			code_challenge_method VARCHAR(16)  NOT NULL,
			nonce                 TEXT         NOT NULL,
			consumed              SMALLINT     NOT NULL DEFAULT 0,
			issued_at             BIGINT       NOT NULL,
			expires_at            BIGINT       NOT NULL,
			issuer                TEXT,
			extension_data        TEXT,
			redirect_uri_omitted  SMALLINT     NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS oauth2_access_tokens (
			token_hash VARCHAR(128) PRIMARY KEY,
			client_id  VARCHAR(255) NOT NULL,
			subject    VARCHAR(255) NOT NULL,
			scope      TEXT         NOT NULL,
			family_id  VARCHAR(64)  NOT NULL,
			audience   VARCHAR(255) NOT NULL,
			issued_at  BIGINT       NOT NULL,
			expires_at BIGINT       NOT NULL,
			issuer         TEXT,
			extension_data TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS oauth2_refresh_tokens (
			token_hash VARCHAR(128) PRIMARY KEY,
			client_id  VARCHAR(255) NOT NULL,
			subject    VARCHAR(255) NOT NULL,
			scope      TEXT         NOT NULL,
			family_id  VARCHAR(64)  NOT NULL,
			consumed   SMALLINT     NOT NULL DEFAULT 0,
			issued_at  BIGINT       NOT NULL,
			expires_at BIGINT       NOT NULL,
			issuer         TEXT,
			extension_data TEXT,
			family_issued_at BIGINT NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS oauth2_token_families (
			family_id  VARCHAR(64)  PRIMARY KEY,
			revoked_at BIGINT       NOT NULL DEFAULT 0,
			expires_at BIGINT       NOT NULL
		)`,
	}
}

// Migrate applies [Schema] to the store's database. It is safe to call
// repeatedly (every statement is IF NOT EXISTS): it creates the missing
// tables and never alters an existing one — the columns a release adds to
// an existing table are added with the statements MIGRATION.md lists,
// through your migration tool, before the release serves traffic.
func (s *Store) Migrate(ctx context.Context) error {
	for _, stmt := range Schema(s.dialect) {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("sqlstore: migrate: %w", err)
		}
	}

	return nil
}
