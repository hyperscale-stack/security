// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package basic provides HTTP Basic authentication for the security core.
//
// It ships an Extractor that reads "Authorization: Basic ..." headers from a
// Carrier, and an Authenticator that consumes a UserLoader + a Hasher to
// validate the username/password pair against a backing store.
//
// Allowed dependencies (per architecture plan):
//   - github.com/hyperscale-stack/security (core)
//   - github.com/hyperscale-stack/security/password (for password hashing)
//   - stdlib only
//
// Real implementation lands in Phase 4.
package basic
