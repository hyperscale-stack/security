// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore

import (
	"context"
	"fmt"
)

// Schema returns the DDL statements that create the three tables backing
// the store, for the given dialect. Timestamps are stored as BIGINT Unix
// seconds to dodge the TIMESTAMP / DATETIME portability minefield between
// engines. Token / code raw values are NEVER stored — only their hashes.
//
// The statements are idempotent (CREATE TABLE IF NOT EXISTS). Production
// deployments typically run them through a migration tool rather than via
// [Store.Migrate], but Migrate is offered for tests and small setups.
func Schema(d Dialect) []string {
	boolType := "BOOLEAN"
	if d.Name() == dialectSQLite {
		boolType = "INTEGER"
	}

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
			issued_at             BIGINT       NOT NULL,
			expires_at            BIGINT       NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS oauth2_access_tokens (
			token_hash VARCHAR(128) PRIMARY KEY,
			client_id  VARCHAR(255) NOT NULL,
			subject    VARCHAR(255) NOT NULL,
			scope      TEXT         NOT NULL,
			family_id  VARCHAR(64)  NOT NULL,
			audience   VARCHAR(255) NOT NULL,
			issued_at  BIGINT       NOT NULL,
			expires_at BIGINT       NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_oauth2_access_family ON oauth2_access_tokens (family_id)`,
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS oauth2_refresh_tokens (
			token_hash VARCHAR(128) PRIMARY KEY,
			client_id  VARCHAR(255) NOT NULL,
			subject    VARCHAR(255) NOT NULL,
			scope      TEXT         NOT NULL,
			family_id  VARCHAR(64)  NOT NULL,
			consumed   %s           NOT NULL DEFAULT 0,
			issued_at  BIGINT       NOT NULL,
			expires_at BIGINT       NOT NULL
		)`, boolType),
		`CREATE INDEX IF NOT EXISTS idx_oauth2_refresh_family ON oauth2_refresh_tokens (family_id)`,
	}
}

// Migrate applies [Schema] to the store's database. It is safe to call
// repeatedly (every statement is IF NOT EXISTS).
func (s *Store) Migrate(ctx context.Context) error {
	for _, stmt := range Schema(s.dialect) {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("sqlstore: migrate: %w", err)
		}
	}

	return nil
}
