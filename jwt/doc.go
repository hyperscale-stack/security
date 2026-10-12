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
//   - MarshalJWKS publishes a JWK Set of public signature keys and refuses
//     private or symmetric material; PublicKey.Validate and
//     PrivateKey.Validate bind every key to one algorithm (RFC 8725 §3.1,
//     RFC 7518 key sizes and curves).
//   - VerifySignature checks a signature and nothing else, for callers that
//     validate claims under their own rules (e.g. an OpenID Provider's
//     id_token_hint); Verifier is the general entry point.
//   - Explicit typing (RFC 8725 §3.11): signers write a "typ" header —
//     "JWT" by default, "at+jwt" for the RFC 9068 access tokens of
//     NewOAuth2AccessTokenSigner — and WithType makes a verifier require one.
//   - Key material is never printed: keys, signers, key sets and verifiers
//     print (every fmt verb), log (slog) and JSON-encode key IDs,
//     algorithms and key types only; an asymmetric PublicKey still
//     JSON-encodes its public fields.
//
// Allowed dependencies:
//   - github.com/hyperscale-stack/security (core)
//   - github.com/hyperscale-stack/security/bearer (TokenVerifier adapter)
//   - github.com/hyperscale-stack/security/oauth2 (access-token signer adapter)
//   - github.com/go-jose/go-jose/v4 (JOSE primitives)
//   - go.opentelemetry.io/otel
//   - stdlib only
package jwtsec
