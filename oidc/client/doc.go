// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package oidcclient is an OpenID Connect Relying Party: it logs users in
// through an OpenID Provider with the Authorization Code flow and returns a
// verified identity — issuer, subject and claims. It serves an identity
// broker federating enterprise identity providers as well as an application
// logging in through such a broker. It does not depend on the OAuth2 server
// or OpenID Provider modules of this repository.
//
// # Profile
//
// One [Client] per connection (provider + client registration + redirect
// URI). [New] discovers the provider metadata from the configured issuer
// (OpenID Connect Discovery 1.0 §4) and requires the metadata issuer to be
// byte-for-byte the configured one (§4.3). [Client.Begin] starts a login —
// Authorization Code with PKCE S256 (RFC 7636), state, nonce — and stores a
// [Transaction] through the application's [TransactionStore];
// [Client.Complete] validates the authorization response, consumes the
// transaction once, redeems the code and validates the ID Token (OpenID
// Connect Core 1.0 §3.1.3.7, plus at_hash when present, §3.1.3.8).
// [Client.UserInfo] fetches profile claims and verifies their subject
// (§5.3.2). [Client.StartLogin] and [Client.HandleCallback] wrap Begin and
// Complete for net/http, cookies included.
//
// Supported: response modes query and form_post; client authentication
// client_secret_basic (identifier and secret form-urlencoded first, RFC 6749
// §2.3.1), client_secret_post and none (public clients, which require the
// provider to advertise S256); ID Tokens signed with RS256/384/512,
// PS256/384/512, ES256/384/512 or EdDSA (Ed25519); RFC 9207 authorization
// response issuer identification; JWK Set rollover.
//
// Not supported, and refused: implicit and hybrid flows, the fragment
// response mode, HMAC-signed (HS256/384/512) or unsigned ID Tokens,
// encrypted ID Tokens, signed or encrypted UserInfo responses, request
// objects, JARM, PAR, DPoP, private_key_jwt and client_secret_jwt. Refresh
// tokens are returned to the application, which redeems them itself.
//
// # Security contract
//
//   - The issuer comes from configuration only, never from a token, a
//     callback parameter or a JOSE header. Keys come from the issuer's
//     jwks_uri only: an ID Token whose header carries jku, x5u, jwk or x5c
//     is refused before it is parsed (OpenID Connect Core §2), as is a
//     header over 4 KiB or that is not strict JSON.
//   - Every outbound request — discovery, JWK Set, token, UserInfo — goes
//     through the outbound package: https, publicly routable destinations,
//     bounded time and size. Token and UserInfo requests never follow
//     redirects; discovery and JWK Set requests follow them only when
//     Config.Outbound.MaxRedirects allows it, and never to another origin
//     than the one requested, so metadata and keys come from the issuer's
//     and the jwks_uri's origins only.
//   - A login transaction is bound to the user agent that started it: Begin
//     returns a binding secret the user agent keeps (an HttpOnly __Host-
//     cookie with the net/http helpers) and the callback presents. The
//     nonce and the PKCE verifier are derived from it with HMAC-SHA256, so
//     the store holds no secret. An integrity MAC over every field of the
//     transaction is keyed by both that secret and a server-held
//     transaction key (Config.TransactionKeys): a transaction altered in
//     the store fails its login, even when the attacker writing to the
//     store runs that login itself — so max_age and acr_values cannot be
//     relaxed through the store. The transaction is also bound to the
//     connection, issuer, client, redirect URI and response mode, expires,
//     and is consumed atomically once. The store is trusted for
//     availability and single consumption only.
//   - Mix-up defense (RFC 9700 §4.4): every connection MUST have its own
//     redirect URI — distinct from every other connection's by scheme,
//     host, port, path or query parameter — and Complete refuses a response
//     received on another URL than the connection's. Providers that
//     advertise RFC 9207 are additionally checked on the iss parameter.
//     Never route callbacks by the state value.
//   - Nothing is returned before the ID Token is fully validated: tokens of
//     a failed login are never exposed (RFC 9700 §4.5.3.2).
//   - Every credential — the client secret, the transaction keys, the
//     binding secret, the tokens — is a [Secret]: it prints, logs and
//     encodes as REDACTED with every fmt verb, log/slog and encoding/json,
//     also when fmt reaches it through an unexported field of another
//     value; Secret.Reveal is the only way to its value.
//   - JSON — the ID Token's JOSE header included — is parsed strictly:
//     duplicate member names, two names that differ only by case, invalid
//     UTF-8 and unpaired surrogate escapes are refused at every nesting
//     level. A lone name that differs from a known
//     claim only by case (EMAIL_VERIFIED) is another claim (OpenID Connect
//     Core §14 compares names code point by code point), ignored as Core §2
//     and RFC 7519 §4 require; encoding/json, which matches struct fields
//     case-insensitively, would read it as the known one: decode claims with
//     Identity.DecodeClaims or UserInfo.Decode (or into a map), and read the
//     validated values from the Identity fields.
//   - The verified identity is Issuer + Subject (OpenID Connect Core §5.7).
//     Never link or merge accounts by email, phone number or username:
//     another subject — or another provider — can assert the same value.
//
// The application owns connection selection and routing, the transaction
// store deployment, account linking and provisioning, its own session
// (create a fresh one after Complete), rate limiting of login starts, and
// tenant isolation. To link an external identity to an account already
// signed in, start the login with a CSRF-protected POST after a recent
// re-authentication, put a random value bound to the local session in
// AuthOptions.AppState, and link only when Identity.AppState matches it.
//
// # Library evaluation
//
// github.com/coreos/go-oidc (v3.21.0) was evaluated and rejected for
// production use. Its IDTokenVerifier checks the signature (with an
// algorithm allow-list), iss (with a hard-coded exception accepting
// "accounts.google.com" without scheme), aud, exp (no leeway) and nbf (a
// fixed 5-minute leeway), but not the nonce, azp, iat, the JOSE typ (an
// RFC 9068 at+jwt access token whose aud is the client would pass),
// auth_time against max_age, nor acr. Its remote key set refetches the JWK
// Set on any verification failure, unknown kid or bad signature alike, with
// de-duplication but no rate limit, and discovery and UserInfo read
// unbounded bodies through an HTTP client without SSRF policy. Using it
// would still require a bounded key set, an outbound policy, body limits,
// the missing claim checks and golang.org/x/oauth2 for the code exchange:
// most of the security-relevant logic would be ours anyway, next to hidden
// behavior outside our control. This package therefore implements the
// OpenID Connect Core §3.1.3.7 checklist itself on top of
// github.com/go-jose/go-jose/v4 for the JOSE primitives. go-oidc and
// golang.org/x/oauth2 are never production dependencies of this
// repository; at most they serve as an independent Relying Party in
// interoperability tests.
//
// Allowed dependencies:
//   - github.com/hyperscale-stack/security (core: outbound, sentinel errors)
//   - github.com/go-jose/go-jose/v4
//   - stdlib only
package oidcclient
