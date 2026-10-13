// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package sqlstores_test runs the three SQL stores of the repository —
// oauth2/store/sql, oidc/client/store/sql and saml/sp/store/sql — on real
// database servers: their Migrate racing on one empty database, the
// advisory lock Migrate takes on PostgreSQL, the oauth2 storage
// conformance suite, and the MySQL upgrade statements of MIGRATION.md. The
// module holds tests only and is never released. SQLite runs everywhere;
// PostgreSQL, MySQL and MariaDB are opt-in (see compose.yaml) and run in
// CI (scripts/test-backends.sh).
package sqlstores_test
