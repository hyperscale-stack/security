// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package voter ships the catalog of stock [security.Voter]
// implementations consumed by [security.AccessDecisionManager].
//
// Each voter Supports a single attribute family (roles, scopes,
// authorities, permissions, or authentication state). Compose them through
// And/Or/Not for richer policies.
//
// Voters are pure (no I/O) and safe for concurrent use.
package voter
