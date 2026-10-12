// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package oidcprovider is an OpenID Provider (OpenID Connect Core 1.0
// incorporating errata set 2) built on the oauth2 authorization server: the
// Authorization Code flow with PKCE, signed ID Tokens, UserInfo, Discovery
// and a public JWK Set — through the oauth2.Extension hooks, without a
// second token endpoint.
//
// The provider owns the protocol: it validates OpenID authentication
// requests (prompt, max_age, nonce, claims, id_token_hint, …), verifies the
// application's authentication result against them, records the
// authentication event with the grant, issues ID Tokens at the code
// exchange and at every refresh, serves UserInfo, and publishes discovery
// metadata and verification keys derived from the server configuration.
// The application owns the rest, through typed interfaces: end-user
// sessions, login and consent user interface and records ([Interaction]),
// end-user claims ([ClaimsSource]), signing keys ([KeySource]), issuers
// (oauth2.IssuerResolver) and static clients (oauth2.ClientStore). The
// module embeds no tenant directory, identity linking or login UI.
//
// Wiring: [New] builds the oauth2.Server the provider extends — it is the
// server's Extension and the owner of its ConsentFunc — and [Provider.Paths]
// tells where to mount each handler for an issuer: exactly the URLs the
// discovery document advertises. Only the Authorization Code flow is
// served; implicit and hybrid flows, request objects, dynamic registration,
// pairwise subjects, encrypted tokens and logout extensions are not, and
// are never advertised. docs/oidc-provider.md holds the exact supported
// feature matrix. No conformance or certification is claimed.
//
// Allowed dependencies:
//   - github.com/hyperscale-stack/security/oauth2
//   - github.com/hyperscale-stack/security/jwt (go-jose stays behind it)
//   - stdlib only
package oidcprovider
