// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package oauth2 is the new modular OAuth2 server. It replaces the legacy
// implementation under authentication/provider/oauth2 (kept for backward
// compatibility until end of Phase 7).
//
// The server is organized by responsibility:
//   - Server agreggates Profile, Storage, Grants, ClientAuth, IssuerResolver.
//   - Profile selects the security baseline (OAuth2.0, OAuth2.0-BCP,
//     OAuth2.1-draft). BCP is the recommended default.
//   - Grants implement authorization_code (PKCE mandatory in BCP/21),
//     client_credentials, refresh_token, plus opt-in legacy password and
//     implicit (refused outside Profile20).
//   - Tokens are opaque by default; refresh tokens and authorization codes
//     are stored hashed. JWT access tokens are available via an adapter to
//     the jwt sub-module (no hard dependency from oauth2 to jwt).
//   - Stores expose atomic ConsumeAuthorizationCode and RotateRefreshToken
//     to guarantee single-use semantics and reuse-detection.
//
// Allowed dependencies (per architecture plan):
//   - github.com/hyperscale-stack/security (core)
//   - go.opentelemetry.io/otel
//   - stdlib only
//
// Real implementation lands in Phase 7.
package oauth2
