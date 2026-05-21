// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package oauth2 is a modular OAuth2 authorization server.
//
// The server is organized by responsibility:
//   - Server aggregates Profile, Storage, Grants, ClientAuth, IssuerResolver.
//   - Profile selects the security baseline (OAuth2.0, OAuth2.0-BCP,
//     OAuth2.1-draft). BCP is the recommended default and is enforced at
//     runtime on the grants (PKCE required, "plain" PKCE refused).
//   - Endpoints: AuthorizeHandler runs the RFC 6749 §3.1 authorization
//     endpoint (authorization_code, and the opt-in legacy implicit flow);
//     TokenHandler, RevokeHandler, IntrospectHandler and MetadataHandler
//     cover the remaining RFC endpoints.
//   - Grants implement authorization_code (with PKCE), client_credentials
//     and refresh_token. The legacy password grant (grant.NewLegacyPassword)
//     is opt-in and refused outside Profile20.
//   - Tokens are opaque by default; refresh tokens and authorization codes
//     are stored hashed. JWT access tokens are available via an adapter to
//     the jwt sub-module (no hard dependency from oauth2 to jwt).
//   - Stores expose atomic ConsumeAuthorizationCode and RotateRefreshToken
//     to guarantee single-use semantics and reuse-detection.
//
// Allowed dependencies:
//   - github.com/hyperscale-stack/security (core)
//   - go.opentelemetry.io/otel
//   - stdlib only
package oauth2
