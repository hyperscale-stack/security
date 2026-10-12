// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package oauth2 is a modular OAuth2 authorization server.
//
// The server is organized by responsibility:
//   - Server aggregates Profile, Storage, Grants, ClientAuth, IssuerResolver.
//   - Profile selects the security baseline (OAuth2.0, OAuth2.0-BCP,
//     OAuth2.1-draft). BCP is the recommended default and is enforced at
//     runtime on the grants (PKCE required, "plain" PKCE refused,
//     refresh-token rotation forced).
//   - Endpoints: AuthorizeHandler runs the RFC 6749 §3.1 authorization
//     endpoint (authorization_code, and the opt-in legacy implicit flow);
//     TokenHandler, RevokeHandler, IntrospectHandler and MetadataHandler
//     cover the remaining RFC endpoints.
//   - IntrospectHandler answers confidential clients only (a public
//     client's client_id is no credential), and the optional
//     ServerConfig.IntrospectionPolicy decides which active tokens each
//     caller may see, enforcing resource and tenant boundaries (RFC 7662
//     §4).
//   - Grants implement authorization_code (with PKCE), client_credentials
//     and refresh_token. The legacy password grant (grant.NewLegacyPassword)
//     is opt-in and refused outside Profile20.
//   - Tokens are opaque by default; refresh tokens and authorization codes
//     are stored hashed. JWT access tokens are available via an adapter to
//     the jwt sub-module (no hard dependency from oauth2 to jwt).
//   - Stores expose an atomic ConsumeAuthorizationCode (single use;
//     consumed codes are kept until they expire, so a replayed code revokes
//     the tokens issued from it), and persist every token pair atomically —
//     SaveTokenPair, and RotateRefreshToken with reuse detection — against
//     one authoritative state per token family: once revoked, no token of
//     the family is usable and none can be issued into it (see Storage).
//   - ServerConfig.OnError (and grant.Config.OnError) observe the errors the
//     protocol hides: the cause of a server_error, which never reaches the
//     wire, the storage failures of /revoke — an unfinished revocation
//     answers a bare 503 (RFC 7009 §2.2.1) — a family revocation that
//     failed after a refresh-token reuse or an authorization-code replay,
//     and a failed IntrospectionPolicy. See ErrorHook.
//   - Every authorization is bound to the issuer the IssuerResolver
//     returned at /authorize: the code and every token record it, and the
//     authorization_code and refresh_token grants refuse them at another
//     issuer. Every authorization response names that issuer in its iss
//     parameter (RFC 9207), errors included. A client implementing
//     IssuerBoundClient is unknown at the issuers it is not registered at.
//   - ServerConfig.Extension plugs an optional protocol extension — the
//     oidc/provider module's OpenID Provider — into the authorization-code
//     flow: it validates its own /authorize parameters after the core
//     checks, turns the application's trusted authentication result
//     (Consent.ExtensionResult) into the grant context the code and every
//     token derived from it record (ExtensionData, unchanged across
//     refreshes), and adds an id_token to the token response before
//     anything is persisted. A ConsentFunc refuses with an OpenID Connect
//     code through Consent.Refusal. See Extension.
//
// Allowed dependencies:
//   - github.com/hyperscale-stack/security (core)
//   - go.opentelemetry.io/otel
//   - stdlib only
package oauth2
