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
// A legacy NewQueryExtractor is offered for the deprecated "?access_token="
// query parameter (RFC 6750 §2.3); its godoc warns against using it.
//
// Allowed dependencies:
//   - github.com/hyperscale-stack/security (core)
//   - stdlib only
package bearer
