# Security considerations

This document records the security posture of the library: the defaults it
ships, the attacks it defends against, and the choices left to the operator.

## Password hashing

Two `password.Hasher` implementations are shipped:

- **bcrypt** — `NewBCryptHasher(cost)`. Constant-time comparison is provided
  by `golang.org/x/crypto/bcrypt`.
- **Argon2id** — `NewArgon2idHasher(params)`. The default profile
  (`DefaultArgon2idParams`) follows RFC 9106 §4 / OWASP 2024: memory 19 MiB,
  time 2, parallelism 1, 32-byte key, 16-byte salt.

`NeedsRehash` lets a login flow transparently upgrade a stored hash when the
operator raises the cost factor. Call it after a successful `Verify` and
re-hash if it returns true.

A plain mismatch returns `(false, nil)` — only malformed input or context
cancellation produces an error. Never store or log the cleartext password.

## Account enumeration

`basic.Authenticator` collapses every failure — unknown user, loader error,
disabled/locked/expired account, password mismatch — into a single
`security.ErrInvalidCredentials` at the client boundary. The detailed cause
stays in the wrapped error chain for server-side telemetry only. Do not
mirror the detailed cause in the HTTP/gRPC response.

## JWT

`jwtsec` defends against the two classic JWT attacks:

- **`alg=none`** — rejected. The verifier parses with an explicit algorithm
  allowlist, so an unsigned token never reaches key resolution.
- **Algorithm confusion** (HS256 forged with an RSA public key) — the
  default allowlist is asymmetric only: `RS256/384/512`, `PS256/384/512`,
  `ES256/384/512`, `EdDSA`. HMAC algorithms are **not** allowed by default;
  enable them with `WithAllowedAlgorithms` only when both ends share a
  symmetric secret and you understand the trade-off.

The verifier also validates `iss`, `aud`, `exp`, `nbf`, and `iat` with a
configurable clock skew, and resolves keys by `kid` against a JWKS provider
(static or cached-remote).

## OAuth2

- **PKCE** — `authorization_code` requires PKCE under `Profile20BCP` and
  `Profile21Draft`; under `Profile20` it is optional unless
  `grant.Config.RequirePKCE` is set. `S256` is the only method accepted
  under BCP / 2.1; `plain` is tolerated only under `Profile20`. Both ends
  enforce the RFC 7636 syntax: `/authorize` answers `invalid_request` to a
  `code_challenge` that is not 43–128 unreserved characters (`plain`) or
  not the unpadded base64url SHA-256 digest (`S256`), and, for a code
  bound to a `code_challenge`, `/token` answers `invalid_grant` to a
  `code_verifier` that is not 43–128 unreserved characters. The code is
  consumed whether the verifier is malformed or wrong. Well-formed
  verifiers are compared in constant time.
- **Refresh-token rotation** — mandatory under `Profile20BCP` (the default)
  and `Profile21Draft`, whatever `grant.Config.RotateRefreshTokens` says:
  every refresh exchange consumes the presented token and issues a new one
  in the same family (RFC 9700 §4.14.2). The profiles apply it to every
  client, stricter than RFC 9700 §2.2.2, which requires rotation — or
  sender-constrained refresh tokens, which this library does not issue — for
  public clients only. Under these profiles — and under `Profile20` when
  `RotateRefreshTokens` is set — `NewServer` refuses a `refresh_token` grant
  without a `RefreshTokens` generator, and the grant itself fails with
  `server_error` before minting anything when it cannot rotate. Re-use of an
  already-rotated token is treated as theft: the whole family is revoked
  (`ErrRefreshTokenReused`), with the guarantees described under
  [Token-family revocation](#token-family-revocation-storage-guarantees).
  Clients MUST keep the refresh token returned by each exchange (RFC 6749
  §6) and must not refresh concurrently with the same token, or they lose
  the family. Under `Profile20` rotation is opt-in (`RotateRefreshTokens`);
  without it a refresh token stays reusable until it expires, which RFC 9700
  §2.2.2 forbids for public clients.
- **Token storage** — access tokens, refresh tokens, and authorization
  codes are stored **hashed only** (SHA-256, via `oauth2.HashToken`). The
  store never sees cleartext, so a database compromise does not yield
  usable tokens. Tokens carry ≥ 128 bits of entropy, so the bare hash is
  preimage- and brute-force-resistant.
- **Atomic single-use** — `ConsumeAuthorizationCode` is atomic in every
  `Storage` implementation, and so are the token writes: `SaveTokenPair`
  and `RotateRefreshToken` persist a whole pair or nothing, gated by the
  token family (SQL transactions with row locks, Redis Lua scripts, a mutex
  in memory). Concurrent use of the same code or refresh token yields
  exactly one winner; the conformance suite checks it with 50 concurrent
  consumers of one code and 30 concurrent rotations of one token, and races
  revocations against rotation chains and issuance.
- **Authorization-code replay** — exchanging a consumed code is refused with
  `invalid_grant`, and the tokens its first exchange issued are revoked:
  access and refresh tokens, and every later rotation (RFC 6749 §4.1.2,
  §10.5; RFC 9700 §4.2.4). Only a replay that would itself have been
  accepted revokes: the code has not expired, and the client it was issued
  to presents it with the same `redirect_uri` and PKCE verifier and may
  still use `authorization_code` (OAuth 2.1 §4.1.3, §7.5.3). Anything else —
  another client, a missing or wrong verifier, an unknown code — is refused
  and revokes nothing: a public `client_id` is no secret, and revoking on
  any replay would let whoever holds a leaked code cut the client off. The
  grant derives the code's token family from the code before consuming it,
  so the link takes no storage and a replay racing the first exchange cannot
  leave its tokens active: one landing before that exchange persists its
  tokens makes it answer `invalid_grant` and issue nothing; one landing
  after revokes them. The first outcome holds while the store keeps the
  family's revoked record (`oauth2.FamilyRevocationRetention` at least),
  i.e. under the [deployment
  requirements](#token-family-revocation-storage-guarantees): an evicted
  Redis family key, or a SQL family row deleted before its `expires_at`,
  lets the in-flight exchange recreate the family active. Stores keep a
  consumed code, hashed and flagged, at least until it expires — Redis
  expires the key with the code, SQL rows stay until your cleanup, the
  memory store keeps them for good — so a replay is recognized for the
  code's lifetime (`AuthorizeConfig.CodeTTL`, 10 minutes by default); a
  later one is refused like any replay, and revokes nothing. A failed
  revocation reaches `grant.Config.OnError`, and the next proven replay
  retries it. A legitimate client retrying a lost response, or submitting a
  code twice, revokes its own tokens: a code MUST NOT be reused (RFC 6749
  §4.1.2). Access tokens validated offline are out of reach, see [Offline
  JWT access tokens](#offline-jwt-access-tokens).
- **Profiles** — `Profile20BCP` (the default) follows the OAuth 2.0
  Security BCP: it refuses the `implicit` grant. `Profile21Draft`
  additionally refuses the `password` grant. Legacy grants are opt-in and
  refused outright under the stricter profile.
- **Client authentication** — `client_secret_basic` / `client_secret_post`
  compare secrets in constant time and never accept an empty one. Basic
  answers an empty password or a missing `client_id` with
  `401 invalid_client` before loading the client, the same answer whether
  or not the client exists; a form with an empty or absent `client_secret`
  is a `none` request, which only public clients may make. Custom
  `SecretMatcher`s MUST NOT match an empty secret; `DefaultClient` never
  matches an empty `Secret`. A public client has no secret: it
  authenticates with `none` (RFC 7591 §2) and MUST use PKCE. Register as
  public a client that cannot keep its credentials confidential (RFC 6749
  §2.1). `/introspect` answers `ClientConfidential` callers only: a public
  client (whatever the method, `none` included) or an untyped client gets
  `401 invalid_client`.
- **Token introspection** — RFC 7662 §4 requires the authorization server
  to authenticate the protected resources calling `/introspect`. A public
  client cannot authenticate: its `client_id` ships inside every copy of the
  app and RFC 6749 §2.2 forbids using it alone, and the authorization server
  MUST NOT rely on a public client's authentication — even with a secret —
  to identify it (RFC 6749 §2.3). Accepting one would let anyone read the
  validity and claims of a token they held — through `none`, or through
  Basic/Post with the client's registered secret — so `/introspect` refuses
  every caller that is not a confidential client. By default, any
  authenticated confidential client may then introspect any token.
  RFC 7662 §4 adds that protected resources SHOULD be specifically
  authorized, and that when a token can be used only at certain resource
  servers the authorization server MUST determine whether it can be used at
  the caller: that decision is `ServerConfig.IntrospectionPolicy`, which
  sees the authenticated caller and the token's metadata before anything is
  disclosed. Refuse refresh tokens to resource servers — they are meant for
  the client alone, and a resource server that ignores `token_type` could
  accept one as a bearer token. A withheld token and a failed policy answer
  the same bytes as an unknown token (`{"active":false}`), so the response
  discloses nothing (its latency may still differ); a policy failure is
  reported to `OnError`.

### Token-family revocation (storage guarantees)

Every access and refresh token issued from one authorization shares a token
family; `client_credentials` and implicit tokens belong to none. Revoking
the family is how the server answers a replayed refresh token (RFC 9700
§4.14.2, RFC 6749 §10.4) and how `/revoke` honours RFC 7009 §2.1, which asks
the server to invalidate the access tokens of a revoked refresh token's
grant (and allows revoking the refresh tokens of a revoked access token).
Every `Storage` keeps one authoritative state per family — active or
revoked — that issuance, rotation and lookups go through, so a revocation
never has to find the family's tokens:

- **Complete revocation.** A revocation is complete once
  `RevokeRefreshFamily` returned `nil`, or once a reuse was reported without
  `oauth2.ErrTokenFamilyRevocationFailed`. From then on no token of the
  family is usable through the store — access-token lookups fail with
  `invalid_grant`, refresh tokens read consumed — and every issuance or
  rotation into the family fails without persisting anything, including one
  that raced the revocation: it is ordered either before the revocation,
  which then covers its tokens, or after it, and is refused. A lookup
  running concurrently with the revocation may still answer "active".
- **Before the first token.** A family can be revoked before any of its
  tokens exists; the revocation is kept for at least
  `oauth2.FamilyRevocationRetention` (24 hours), and never for less than the
  lifetime of the family's tokens, so a late issuance is still refused.
- **Atomicity.** A failed issuance or rotation persists no token and
  consumes nothing: a failed exchange no longer leaves an access token
  behind.
- **Idempotence and isolation.** Revoking a revoked family changes nothing
  and succeeds; a revoked family never becomes active again. Revoking one
  family affects no other family and no token outside a family, and the
  empty family ID is refused.
- **Failure.** A revocation that cannot be recorded fails with
  `oauth2.ErrTokenFamilyRevocationFailed`, and its outcome may be unknown (a
  lost acknowledgement): treat the family as active and retry, which
  idempotence makes safe. `/revoke` then answers
  `503 temporarily_unavailable` — RFC 7009 §2.2.1: the client must assume
  the token still exists and may retry — since a `200` would tell the client
  the token can no longer be used (RFC 7009 §2.1). It revokes an access
  token's family before deleting the token, so a failed family revocation
  leaves everything in place for that retry. On the reuse path the store
  reports `ErrRefreshTokenReused` joined with the revocation failure, the
  `refresh_token` grant retries the revocation on a context detached from
  the request, and a second failure reaches `grant.Config.OnError`; the
  client gets `invalid_grant` either way.
- **Fail closed.** A token whose family state is missing — expired,
  evicted, deleted by a premature cleanup, or never written by a build
  predating token families — is treated as revoked. This protects lookups
  only: the next issuance into a family whose revoked state was lost records
  it active again and revives its tokens, so a revoked family's state must
  never be lost within its retention — no eviction, no early cleanup.
- **Lost responses look like theft.** When the response to a successful
  rotation is lost, the client retries with the presented token, which is
  now a reuse: the family is revoked and the user re-authenticates. This is
  inherent to rotation; there is no grace period. A Redis rotation resent
  by the client library after a lost reply is recognized, though, and does
  not count as a reuse.

These guarantees rest on deployment assumptions, detailed in the package
documentation of [`store/sql`](../oauth2/store/sql/doc.go) and
[`store/redis`](../oauth2/store/redis/doc.go): every read reaches the
primary (no replica reads, no client-side caching), the store's PostgreSQL
transactions run at READ COMMITTED (it pins the level) and
MySQL tables use InnoDB, Redis is a standalone server or a Sentinel primary
(not Cluster) running 6.0 or later with `maxmemory-policy noeviction`, no
family row or key is deleted before it expires, and durability is the
backend's: a revocation acknowledged by a primary that fails before
persisting or replicating it can be lost in a failover. Only SQLite is
exercised in CI; the PostgreSQL and MySQL guarantees rest on their locking
semantics.

### Offline JWT access tokens

The store's revocation reaches every token looked up in the store —
`/introspect`, a resource server calling `LookupAccessToken` — but not a
resource server that verifies JWT access tokens offline, from their
signature and claims (`jwtsec.BearerVerifier`): such a token stays valid
until its `exp`, whatever happened to its family — including the tokens
revoked after an authorization-code replay: deleting or flagging store
records never invalidates a signature. The RFC 9068 payload the
`jwtsec` signer emits carries no family or token identifier (`jti`), so it
cannot be deny-listed today either. RFC 7009 §2.1 acknowledges such a
propagation delay and asks implementations to minimize it; its §3 leaves
immediate revocation of self-contained tokens to non-standardized backend
interaction, and suggests short-lived access tokens instead. To bound the
window:

- keep `grant.Config.AccessTTL` short when access tokens are JWTs;
- for high-value operations, validate the token against the authorization
  server — RFC 7662 introspection, or `LookupAccessToken` when the resource
  server shares the store — rather than offline;
- or issue opaque access tokens, which only the store can validate.

## Sessions

`session` issues a **stateless encrypted cookie** — there is no server-side
session store to compromise or scale.

- **Confidentiality + integrity** — the cookie payload is sealed with
  AES-256-GCM (AEAD): tampering fails decryption, it is not merely detected.
- **Key rotation** — the `Codec` accepts an ordered key list. New cookies
  are sealed with the first key; decryption is attempted against every key,
  so a key can be retired gracefully.
- **Cookie attributes** — defaults are conservative: `Secure=true`,
  `HttpOnly=true`, `SameSite=Lax`. Disable `Secure` only for local plain-HTTP
  development.
- **Session fixation** — `Manager.Rotate` mints a fresh session ID; call it
  immediately after a privilege change (login). The ID never appears raw in
  a span — only a SHA-256 fingerprint.
- **CSRF** — the synchronizer-token helper (`CSRFToken` / `VerifyCSRF`)
  compares tokens in constant time. The session cookie being `HttpOnly`
  keeps the token out of reach of XSS.
- **Size** — the whole session is JSON-encoded into the cookie; browsers
  cap a cookie near 4 KiB. Keep `Values` small.

## Transport error mapping

Error mappers return terse, code-first responses. HTTP emits a status code
plus a `WWW-Authenticate` challenge; gRPC emits a `codes.Code`. Clients are
expected to branch on the code, not parse the message — the message never
leaks why authentication failed.

## Observability

No secret is ever placed on a span attribute or log line. See
[observability.md](observability.md) for the secrets policy and the full
span catalog.

## Operator checklist

- [ ] Pick a password hasher and review its cost against current hardware.
- [ ] Rotate JWT signing keys; expose them through a JWKS endpoint.
- [ ] Keep the JWT allowlist asymmetric unless you truly need HMAC.
- [ ] Use `Profile20BCP` or stricter; do not enable the `implicit` /
      `password` legacy grants without a documented reason.
- [ ] Give every confidential client that authenticates with a secret a
      high-entropy one. Register a client that cannot keep a secret as
      public (`none` + PKCE), and list its `GrantTypeValues`: an empty
      list allows every grant, `client_credentials` included.
- [ ] Register the resource servers calling `/introspect` as confidential
      clients, and set `ServerConfig.IntrospectionPolicy` when several
      resource servers or tenants share the authorization server.
- [ ] Give `ServerConfig.Storage` and every grant the same store, and wire
      `ServerConfig.OnError` and `grant.Config.OnError` to the same sink:
      failed family revocations are reported there.
- [ ] With `store/sql`, periodically delete rows past `expires_at` —
      consumed authorization codes included, never a family row before
      it — in the deadlock-free order the package documentation gives;
      with `store/redis`, run Redis 6.0+ standalone or behind Sentinel with
      `maxmemory-policy noeviction`, and read from the primary only. A
      revoked family whose state is lost before it expires can be revived.
- [ ] Keep JWT access tokens short-lived: a store revocation does not
      reach resource servers that verify them offline.
- [ ] Serve over HTTPS so `Secure` cookies and bearer tokens are protected.
- [ ] Supply at least two session keys so rotation is possible without
      invalidating live sessions.
- [ ] Install an OpenTelemetry `TracerProvider` to collect the spans.
