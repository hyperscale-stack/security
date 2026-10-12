// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package examples is a container module hosting the use-case examples
// shipped alongside the security library. Each example is a sub-package
// with a runnable main; the package doc comment of every main documents the
// curl / grpcurl probes.
//
// The examples module is free to depend on every other module of the
// workspace (this is the only place where doing so is acceptable).
//
// Available examples:
//
//   - basic-http        — HTTP Basic authentication + role-based authorization.
//   - bearer-jwt        — JWT issuance and Bearer-token validation, scope gating.
//   - grpc-bearer       — gRPC unary interceptors authenticating a Bearer JWT.
//   - connectrpc-bearer — ConnectRPC interceptors authenticating a Bearer JWT.
//   - session-web       — cookie-session login form with a CSRF-protected logout.
//   - oauth2            — OAuth2 authorization server + Bearer resource server.
//   - oidc-client       — OpenID Connect sign-in through external providers.
//   - oidc-provider     — OpenID Provider with its own login and consent pages.
//   - saml-sp           — SAML 2.0 Service Provider: SP-initiated login with an enterprise IdP.
package examples
