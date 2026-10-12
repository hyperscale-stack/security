// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore

import (
	"context"
	"fmt"
)

// Schema returns the DDL of the two tables backing the store:
//
//   - samlsp_transactions: one row per login transaction, keyed by the
//     digest of (connection, RelayState handle); binding_hash is the digest
//     of the browser-binding cookie; payload is opaque SP state; consumed is
//     0 or 1; expires_at is in Unix seconds.
//   - samlsp_used_assertions: one row per consumed assertion, keyed by the
//     digest of (issuer, assertion ID), kept at least until expires_at.
//
// No secret is stored: keys and binding values are SHA-256 digests. The DDL
// is the same for every Dialect (portable types, no BOOLEAN, no index);
// the argument is accepted for API stability. The statements are
// idempotent (CREATE TABLE IF NOT EXISTS).
func Schema(_ Dialect) []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS samlsp_transactions (
			id           VARCHAR(64) PRIMARY KEY,
			binding_hash VARCHAR(64) NOT NULL,
			payload      TEXT        NOT NULL,
			consumed     SMALLINT    NOT NULL DEFAULT 0,
			expires_at   BIGINT      NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS samlsp_used_assertions (
			assertion_key VARCHAR(64) PRIMARY KEY,
			expires_at    BIGINT      NOT NULL
		)`,
	}
}

// Migrate applies Schema; it is safe to call repeatedly and never alters an
// existing table.
func (s *Store) Migrate(ctx context.Context) error {
	for _, stmt := range Schema(s.dialect) {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("sqlstore: migrate: %w", err)
		}
	}

	return nil
}
