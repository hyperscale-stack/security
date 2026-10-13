// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package basic provides HTTP Basic authentication for the security core.
//
// It ships an Extractor that reads "Authorization: Basic ..." headers from a
// Carrier, and an Authenticator that consumes a UserLoader + a Hasher to
// validate the username/password pair against a backing store.
//
// The Extractor parses RFC 7617 credentials strictly (canonical base64, UTF-8
// without control, format or separator characters, bounded length). The
// Authenticator checks the same rules — form logins can build the value with
// New — then spends exactly one password verification on every attempt,
// unknown accounts included, so that the response time reveals nothing; at
// most runtime.GOMAXPROCS(0) verifications run at once.
//
// Allowed dependencies:
//   - github.com/hyperscale-stack/security (core)
//   - github.com/hyperscale-stack/security/password (for password hashing)
//   - stdlib only
package basic
