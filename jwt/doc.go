// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package jwtsec provides JWT signing and verification with JWKS support and
// key rotation, usable standalone (as a Bearer TokenVerifier) or as the
// signer behind the OAuth2 server's JWT access-token format.
//
// Security defaults:
//   - "alg=none" is rejected unconditionally.
//   - The allowed-algorithm list is mandatory (RS256/ES256/EdDSA by default,
//     HS256 only on explicit opt-in to avoid key confusion).
//   - Issuer and audience are validated by default.
//
// Allowed dependencies (per architecture plan):
//   - github.com/hyperscale-stack/security (core)
//   - github.com/go-jose/go-jose/v4 (JOSE primitives — to be confirmed)
//   - go.opentelemetry.io/otel
//   - stdlib only
//
// Real implementation lands in Phase 6.
package jwtsec
