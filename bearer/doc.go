// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package bearer provides Bearer token extraction and an Authenticator that
// delegates token validation to a pluggable TokenVerifier.
//
// The TokenVerifier interface lets users plug an opaque-token verifier
// (calling a remote introspection endpoint), a local JWT verifier (see the
// jwt sub-module), or any custom scheme.
//
// Only the Authorization-header scheme (RFC 6750 §2.1) is supported;
// query-parameter tokens (§2.3) are intentionally not offered — they leak
// into access logs, browser history, and Referer headers.
//
// Allowed dependencies:
//   - github.com/hyperscale-stack/security (core)
//   - stdlib only
package bearer
