// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package sqlstore is a database/sql implementation of oauth2.Storage with
// real atomicity (transactional ConsumeAuthorizationCode and
// RotateRefreshToken). Dialects supported: PostgreSQL, MySQL, SQLite.
//
// Allowed dependencies (per architecture plan):
//   - github.com/hyperscale-stack/security/oauth2
//   - database/sql
//   - stdlib only (drivers are pluggable; users bring their own)
//
// Real implementation lands in Phase 8.
package sqlstore
