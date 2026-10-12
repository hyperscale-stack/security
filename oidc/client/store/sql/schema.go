// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore

import (
	"context"
	"fmt"
)

// Schema returns the DDL of the table backing the store,
// oidc_client_transactions: one row per pending login, keyed by the state
// hash. Timestamps are BIGINT Unix seconds, which every engine stores
// alike; app_state holds the application state base64-encoded, so that any
// UTF-8 — NUL included, which PostgreSQL text refuses — round-trips whatever
// the column character set; integrity holds the transaction's MAC. No column
// holds a secret (see oidcclient.Transaction).
//
// The DDL sticks to the subset every supported engine accepts, so it is
// the same for every [Dialect]: the argument is accepted for API stability
// and ignored. It creates no index — MySQL has no CREATE INDEX IF NOT
// EXISTS — see the package documentation for the one on expires_at.
//
// The statement is idempotent (CREATE TABLE IF NOT EXISTS). Production
// deployments typically run it through a migration tool rather than via
// [Store.Migrate].
func Schema(_ Dialect) []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS oidc_client_transactions (
			state_hash    VARCHAR(64)  PRIMARY KEY,
			binding_hash  VARCHAR(64)  NOT NULL,
			connection_id VARCHAR(255) NOT NULL,
			issuer        TEXT         NOT NULL,
			client_id     TEXT         NOT NULL,
			redirect_uri  TEXT         NOT NULL,
			response_mode VARCHAR(16)  NOT NULL,
			max_age       BIGINT       NOT NULL,
			acr_values    TEXT         NOT NULL,
			app_state     TEXT         NOT NULL,
			created_at    BIGINT       NOT NULL,
			expires_at    BIGINT       NOT NULL,
			integrity     VARCHAR(64)  NOT NULL
		)`,
	}
}

// Migrate applies [Schema] to the store's database. It is safe to call
// repeatedly: it creates the table when missing and never alters it.
func (s *Store) Migrate(ctx context.Context) error {
	for _, stmt := range Schema(s.dialect) {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("sqlstore: migrate: %w", err)
		}
	}

	return nil
}
