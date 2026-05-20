// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package jwtsec provides JWT signing and verification with JWKS support and
// key rotation, usable standalone (as a Bearer TokenVerifier) or as the
// signer behind the OAuth2 server's JWT access-token format.
//
// Security defaults:
//   - "alg=none" is rejected unconditionally.
//   - The allowed-algorithm list defaults to the asymmetric schemes
//     (RSA, RSA-PSS, ECDSA, EdDSA); HMAC algorithms are accepted only on
//     explicit opt-in via WithAllowedAlgorithms, to avoid key confusion.
//   - Issuer and audience checks are opt-in via WithIssuer / WithAudience.
//
// Allowed dependencies:
//   - github.com/hyperscale-stack/security (core)
//   - github.com/hyperscale-stack/security/bearer (TokenVerifier adapter)
//   - github.com/hyperscale-stack/security/oauth2 (access-token signer adapter)
//   - github.com/go-jose/go-jose/v4 (JOSE primitives)
//   - go.opentelemetry.io/otel
//   - stdlib only
package jwtsec
