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

- **Token confusion** (RFC 8725 §3.11–§3.12) — the OAuth2 access tokens
  `NewOAuth2AccessTokenSigner` signs are typed `at+jwt` and carry a `jti`
  (RFC 9068 §2.1, §2.2); OpenID Connect ID Tokens are typed `JWT`. A resource
  server verifies with `WithType(TypeAccessToken)` — RFC 9068 §4 requires it
  to refuse any other `typ` — so an ID Token signed by the same keys is not
  accepted as an access token. The check is opt-in: verifiers of other JWTs
  keep accepting any `typ`.

## OAuth2

- **PKCE** — `authorization_code` requires PKCE under `Profile20BCP` and
  `Profile21Draft`, and of every client that is not confidential — public
  or untyped — under every profile (RFC 9700 §2.1.1); under `Profile20` it
  is optional for a confidential client unless `grant.Config.RequirePKCE`
  is set. `S256` is the only method accepted
  under BCP / 2.1; `plain` is tolerated only under `Profile20`. Both ends
  enforce the RFC 7636 syntax: `/authorize` answers `invalid_request` to a
  `code_challenge` that is not 43–128 unreserved characters (`plain`) or
  not the unpadded base64url SHA-256 digest (`S256`), and, for a code
  bound to a `code_challenge`, `/token` answers `invalid_grant` to a
  `code_verifier` that is not 43–128 unreserved characters. The code is
  consumed whether the verifier is malformed or wrong. Well-formed
  verifiers are compared in constant time. A `code_verifier` sent for a
  code issued without `code_challenge` is refused with `invalid_grant`
  under every profile (RFC 9700 §4.8.2, the PKCE downgrade attack: an
  attacker strips `code_challenge` from its own authorization request and
  injects the code into a victim's session); a parameter without value
  counts as absent (RFC 6749 §3.1). The refusal burns the code but revokes
  nothing: a replay of a code redeemed without PKCE still revokes its
  tokens, whatever `code_verifier` it carries.
- **Client policy** — fail closed: a client may use only the grant types it
  declares (`Client.GrantTypes`, compared exactly; empty allows none) and
  request only the scopes it declares (`Client.Scopes`; empty allows none).
  `/token` checks the grant type for every grant, custom ones included,
  before the grant runs, so a refused request consumes nothing, and
  `/authorize` checks the grant of the response type (`authorization_code`
  for `code`, `implicit` for `token`) before the extension and the
  `ConsentFunc` run;
  `client_credentials` refuses every client that is not confidential (RFC
  6749 §4.4); a consent narrows the requested scope, never broadens it; a
  refresh token goes only to a client declaring `refresh_token` (RFC 9700
  §4.14.2), and a refresh issues an access token only within the client's
  current scope registration, so shrinking a registration takes effect at
  the next refresh. Refusals caused by an empty declaration reach `OnError` with
  `ErrNoGrantTypesDeclared` / `ErrNoScopesDeclared` as cause. Unlike RFC
  7591 §2, an empty grant-type list implies nothing, and scopes outside the
  registration are refused rather than ignored (OpenID Connect Core
  §3.1.2.1 says unknown scope values SHOULD be ignored).
- **Request parameters** — the parameters each endpoint reads are
  single-valued (RFC 6749 §3.1, §3.2): an empty occurrence is omitted, and
  one included more than once with a value is refused — at `/authorize` a
  repeated `client_id`, `redirect_uri` or `response_mode` with a bare `400`,
  any other with `invalid_request`; at `/token`, `/revoke` and
  `/introspect` with `invalid_request`, before the grant or the lookup
  runs. Callbacks get the request as received: a `ConsentFunc` or an
  `Extension` reads the core's parameters from the `AuthorizeRequest`, never
  with `r.FormValue`, which an empty occurrence can mislead.
- **Scope values** — every scope a client or a callback sends (the `scope`
  of `/authorize` and `/token`, `Consent.Scope`, `ExtensionGrant.Scope`) is
  parsed strictly as RFC 6749 §3.3 tokens — printable ASCII but `"` and `\`
  (NQCHAR), separated by SP; runs of SP and leading or trailing SPs are
  tolerated, any other whitespace is not — at most 100 tokens (repetitions
  included) and 4096 bytes. Anything else is `invalid_scope` (`server_error`
  for an extension), refused before the value is compared with anything.
  Comparisons are set lookups, so the work a request causes stays linear in
  its bounded size, and the server issues and stores scopes canonical:
  single-SP joined, duplicates dropped. A registered scope outside that
  syntax can never be requested; a scope the server stored itself is never
  refused for its syntax.
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
  the family. `RefreshTTL` is an inactivity expiry that every rotation
  restarts; `grant.Config.RefreshFamilyTTL` adds an absolute bound from the
  family's first issuance (`RefreshToken.FamilyIssuedAt`), which also ends a
  family a thief keeps alive by rotating a stolen token — zero, the
  default, sets none. Under `Profile20` rotation is opt-in (`RotateRefreshTokens`)
  for confidential clients only: without it their refresh token stays
  reusable until it expires, while the refresh token of a client that is
  not confidential — public or untyped — always rotates (RFC 9700 §2.2.2,
  §4.14.2); a `refresh_token` grant without a `RefreshTokens` generator then
  fails their refresh with `server_error`, which `NewServer` cannot detect.
- **Token storage** — access tokens, refresh tokens, and authorization
  codes are stored **hashed only** (HMAC-SHA256 with an empty key, via
  `oauth2.HashToken`). The store never sees cleartext, so a database
  compromise does not yield usable tokens. Tokens carry ≥ 128 bits of
  entropy, so the unkeyed hash is preimage- and brute-force-resistant.
- **Codes are consumed before they are validated** — a party holding a
  leaked code can burn it (presenting it with a wrong verifier, or as
  another client): it obtains nothing — client, issuer, redirect URI and
  PKCE still bind the code — but the legitimate exchange then fails with
  `invalid_grant` and the user authorizes again. This is deliberate:
  single use rests on one atomic consumption, validating first would need
  a non-consuming lookup in every store, and refusing a code that has
  leaked is the conservative outcome (RFC 6749 §4.1.2 requires refusing a
  reused code). Keep codes out of logs and `Referer` headers, and
  short-lived (`AuthorizeConfig.CodeTTL`).
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
  Security BCP and `Profile21Draft` the OAuth 2.1 draft: both refuse the
  legacy `implicit` and `password` grants, which only `Profile20` allows —
  opt-in, never by default.
- **Client authentication** — one method per request (RFC 6749 §2.3): an
  `Authorization` header with a body `client_secret`, several
  `Authorization` fields, or a repeated `client_id` / `client_secret` are
  `invalid_request` before any client is loaded, and a body `client_id`
  naming another client than the one authenticated is refused.
  `client_secret_basic` / `client_secret_post`
  compare secrets in constant time and never accept an empty one. Basic
  form-decodes the user-id and password (RFC 6749 §2.3.1, Appendix B) after
  splitting them at the first colon, refuses an invalid escape as a
  malformed header, and answers an empty decoded password or a missing
  `client_id` with
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
- **Issuer binding (realms)** — a subject is only meaningful within its
  issuer (OIDC Core §16.15). Every endpoint resolves the issuer of the
  request through the `IssuerResolver` before it loads the client;
  the code and every token record it, and the `authorization_code` and
  `refresh_token` grants refuse, with `invalid_grant`, a code or refresh
  token issued under another issuer than the one resolved at `/token` — so a
  client registered in several realms cannot carry an authorization across
  them. A refused refresh consumes nothing; a code replayed at another issuer
  revokes nothing, since it could not have redeemed the code — while a
  consumed refresh token presented at another issuer still revokes its
  family, the reuse check coming first (RFC 9700 §4.14.2). Records written
  before issuers were recorded fail closed. The resolver is the realm
  boundary: it must return the same issuer for `/authorize` and `/token` of
  a realm, and the `ConsentFunc` must authenticate the resource owner within
  `AuthorizeRequest.Issuer` — a session of another realm is no
  authentication. `IntrospectedToken.Issuer` lets an `IntrospectionPolicy`
  enforce the same boundary.
- **Clients and realms** — one `ClientStore` behind several issuers makes
  every client known at every issuer: a client of realm A could send realm
  B's end-users to B's genuine login page and obtain their codes and
  tokens once they consent. A client implementing `IssuerBoundClient`
  (`DefaultClient.IssuerValues`) exists at its issuers only: elsewhere
  `/authorize` answers the bare 400 of an unknown `client_id`, never
  redirected (RFC 6749 §4.1.2.1), and `/token`, `/revoke` and `/introspect`
  fail its authentication as an unknown client's (`401 invalid_client`,
  "unknown client"), whatever the secret — the same bytes in both cases, so
  realm B can neither be used by A's clients nor enumerate them or check
  their secrets. The binding is checked before the client's secret and
  redirect URI, and again on the client an authenticator returns. A
  multi-issuer deployment binds every client, or scopes its `ClientStore`
  by issuer.
- **Authorization responses** — a `response_mode` other than the one the
  server answers in (`query` for the code flow, `fragment` for an enabled
  implicit flow) gets a bare 400, never redirected: the answer could not be
  encoded as the client expects (OIDC Core 1.0 incorporating errata set 2,
  §3.1.2.6). Redirected errors carry only the codes the authorization
  endpoint defines (RFC 6749 §4.1.2.1, OIDC Core §3.1.2.6); descriptions and
  `error_uri`s outside the RFC 6749 charset are left out, and the server's
  own descriptions never echo the request. An approval names its subject —
  non-empty, at most 255 bytes — or fails closed with `server_error`. A
  `ConsentFunc` refuses with a protocol code through `Consent.Refusal`; a
  `ConsentFunc` error is always a `server_error`. A refusal's description
  and URI travel in the client's URL — browser history, logs, `Referer` —
  so they must never carry personal data.
- **Mix-up defense (RFC 9207)** — every authorization response, code and
  implicit, success and redirected error, carries `iss`, the issuer the
  request resolved to, and the RFC 8414 metadata sets
  `authorization_response_iss_parameter_supported`: a client talking to
  several authorization servers — or to several realms of one
  `IssuerResolver` — compares it with the issuer it sent the request to and
  aborts on a mismatch (RFC 9700 §4.4.2.1), the defense RFC 9700 prefers to
  distinct redirect URIs. The issuer must therefore be a stable https URL
  without query or fragment (RFC 9207 §2): the server sends it as the
  resolver returns it. The one response without `iss` is the `server_error`
  answering an `IssuerResolver` failure — no issuer is known then. RFC 9207
  §2 asks for `iss` in error responses too, and §2.4 has RFC 9207 clients
  reject a response without it, so the independent code review of #84
  recommended a bare 500 instead; the redirect is kept so that RFC 6749
  clients learn of the failure (RFC 6749 §4.1.2.1 `server_error`), and RFC
  9207 clients discard it as they discard any response they cannot
  attribute — a documented deviation on a server-failure path that issues
  nothing.

### Protocol extensions

`ServerConfig.Extension` (`oauth2.Extension`) is trusted code — the
`oidc/provider` OpenID Provider, or the application's own — plugged into the
authorization-code flow. The server keeps every OAuth 2.0 check and runs it
first:

- **Bounded authority.** The extension only sees requests and exchanges the
  core accepted (client, redirect URI, response mode and type, scope, PKCE;
  client, issuer, redirect URI, verifier and expiry at `/token`). It can
  narrow a granted scope, never broaden it, and add an `id_token` member to
  a token response, never replace `access_token`, `token_type`,
  `expires_in`, `refresh_token` or `scope` — the response members are typed
  fields, not a map. Callbacks get read-only copies of the validated
  request: a `ConsentFunc` or extension hook that modifies its copy — the
  redirect URI, the state, the scope, the PKCE parameters, the nonce, the
  issuer, the client's identity — fails the authorization closed with
  `server_error` (`oauth2.ErrAuthorizeRequestModified`) rather than having
  its rewrite either honored or silently ignored; a grant narrows only
  through `Consent.Scope` and `ExtensionGrant.Scope`.
- **Grant context.** What `CompleteAuthorization` records (`ExtensionData`:
  at most 4096 bytes of UTF-8 without NUL, so every store keeps it
  byte-exact) is persisted with the code and copied onto every token derived
  from it; the stores refuse a refresh-token rotation that would change it,
  or the issuer. It can only be read back through the record its own code or
  refresh token designates: it cannot be substituted across clients,
  issuers, codes or token families, and a refresh never rewrites the
  authentication event it rests on (OIDC Core §12.2).
- **No partial success.** `ExtendTokenResponse` runs after the tokens are
  minted and before their single atomic write: when it fails nothing is
  persisted — a redeemed code stays consumed and a retry is a replay, a
  presented refresh token stays usable — and its `id_token` is dropped when
  the write fails afterwards. A replay of the code that revokes the family
  while the hook runs wins: the exchange in flight answers `invalid_grant`
  without its `id_token`. The hooks must therefore have no externally
  visible side effects.
- **Consumers of the context.** `AccessToken.ExtensionData` is empty for
  tokens no authorization precedes — `client_credentials`, whose `Subject` is
  a client ID, and the legacy `password` grant — and for records written
  before it existed. An endpoint serving end-user data from an access token
  (an OpenID Connect UserInfo endpoint) must require its extension's context
  and an `Issuer` equal to the issuer it serves, or it would serve the
  claims of whatever user shares a subject with a client ID.
- **Integration contracts.** `prompt=none` forbids any login or consent UI
  (OIDC Core §3.1.2.3): a raw `ConsentFunc` that renders a page runs before
  any hook can stop it, so an OpenID provider owns the `ConsentFunc` it
  hands the application. `CompleteAuthorization` binds the authentication
  event it records to `Consent.Subject` and refuses a trusted result it did
  not define. The hooks see the raw `/authorize` form — credentials
  included when a login form posts to it — and the raw access token: they
  must never log or persist either.

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
`jwtsec` signer emits carries a token identifier (`jti`) but no family, and
no deny-list is shipped. RFC 7009 §2.1 acknowledges such a
propagation delay and asks implementations to minimize it; its §3 leaves
immediate revocation of self-contained tokens to non-standardized backend
interaction, and suggests short-lived access tokens instead. To bound the
window:

- keep `grant.Config.AccessTTL` short when access tokens are JWTs;
- for high-value operations, validate the token against the authorization
  server — RFC 7662 introspection, or `LookupAccessToken` when the resource
  server shares the store — rather than offline;
- or issue opaque access tokens, which only the store can validate.

## OpenID Provider

`oidc/provider` trusts the application's `Interaction` for who the end-user
is, never for the protocol rules:

- **Requests are checked before any interaction.** A repeated `client_id`,
  `redirect_uri` or `response_mode`, or a missing `redirect_uri`, answers a
  bare `400` that is never redirected; request objects and `registration`
  are refused; `nonce`, `claims`, `max_age` and hints are bounded; an
  `id_token_hint` must be an ID Token this issuer issued to this client,
  signed by a key it publishes.
- **Every approval is re-checked.** Before a code is issued, the provider
  checks the approval against the request — realm, `prompt=login` and
  `max_age` freshness, designated end-user, essential `acr` — and the
  authentication event itself (a subject of 1 to 255 printable ASCII
  characters, a time at most 5 s in the future, bounded `acr` and `amr`),
  and requires `openid` in the granted scope. A violation issues nothing.
  Freshness is compared at the second of `auth_time`; an application that
  must re-authenticate on `prompt=login` shows its login page itself.
- **`prompt=none` shows no UI**: `AuthorizeSilently` gets no
  `ResponseWriter`, and an OpenID request served outside
  `Provider.AuthorizeHandler` is refused before any `ConsentFunc` runs.
- **Realm-bound authentications.** An authentication counts in the realm
  (issuer) it was established in only. The realm is the issuer: where
  tenancy is finer — one issuer, several organizations — the `Interaction`
  must also check the session's tenant against `Request.Client`. Separate
  issuers isolate sessions, not clients: with one `ClientStore`, bind every
  client to its issuers (`oauth2.IssuerBoundClient`, see "Clients and
  realms" above) — a tenant-A client could otherwise send tenant B's
  end-users to B's genuine login page and obtain their identity and B's
  tokens once they consent. UserInfo refuses a token whose client is no
  longer registered at the issuer.
- **`prompt=none` reveals no session.** The provider's refusals — a
  session of another realm, of another end-user, a stale one, an unmet
  essential `acr` — carry the sentinels' fixed descriptions: on the wire
  they read as no session at all, so a client cannot probe the browser.
  The reason reaches the `ErrorHook` only; an `Interaction` refusing with
  its own description must not describe the session either.
- **`InteractionStartedAt`** must come from server-side state bound to the
  authorization request, never from the session or the request parameters:
  a forged value makes a stale session look fresh. The provider bounds it to
  `[ReceivedAt − 15 min, ReceivedAt + 5 s]` and ignores it under
  `prompt=none`.
- **Offline access needs consent** (OIDC Core §11): `offline_access` is
  dropped unless the end-user consented, and a refresh token issued without
  that consent fails closed. Wire `grant.Config.RefreshTokenScope =
  oidcprovider.ScopeOfflineAccess`.
- **Token confusion** (RFC 9068 §5, RFC 8725 §3.12): an ID Token's audience
  is the client ID, and an access token whose audience equals a client ID is
  refused at issuance; JWT access tokens are typed `at+jwt`. Resource
  servers should require that type (`jwtsec.WithType(jwtsec.TypeAccessToken)`)
  so an ID Token is never accepted as an access token.
- **Keys.** Key rings are validated on every use (RS256 required, one key
  per algorithm and one algorithm per key, RSA of at least 2048 bits, curves
  bound to algorithms) and fail closed; private and symmetric keys are never
  published. The keys of JWT access tokens belong in `KeyRing.Published`:
  one `jwks_uri` serves both (RFC 9068 §4).
- **Claims and accounts.** Only the claims the request and the end-user
  allow are released, and a `ClaimsSource` cannot override a protocol claim.
  `ErrUnknownSubject` stops an OpenID grant at its next exchange; plain
  OAuth 2.0 grants carry no context and are not checked, so disabling an
  end-user must also revoke their token families.
- **UserInfo serves personal data** to bearer tokens of OpenID grants of the
  request's issuer only, with `Cache-Control: no-store`. Allow browser
  origins (CORS) deliberately.
- **Issuers.** The issuer is an https URL without query or fragment
  (`http` only for an explicit loopback development opt-in). Discovery and
  the JWK Set are cacheable (`max-age=300`): an `IssuerResolver` must never
  derive the issuer from an unvalidated `Host` header.
- **The application's pages.** Login and consent pages need CSRF tokens and
  anti-framing headers (`X-Frame-Options: DENY`,
  `Content-Security-Policy: frame-ancestors 'none'`), must validate the URL
  they return to after a login (open redirect), and must never redirect with
  `307` — it would replay the posted credentials (OIDC Core §16.22).
  `examples/oidc-provider` does all of this.
- **Errors.** Refusals reach the `ErrorHook` with their cause; causes never
  carry a token, an `id_token_hint`, a `nonce`, a `login_hint` or a claim
  value.

## SAML Service Provider

`saml/sp` (package `samlsp`) consumes assertions from enterprise identity
providers (SP-initiated Web Browser SSO, Profiles §4.1). An assertion is a
bearer credential delivered through the browser, so the module trusts only
what the operator configured and refuses whatever it cannot read in exactly
one way. This section is the threat model; the
[integration guide](saml-sp.md) gives the exact trust tables, the identity
mapping, the deployment and rollover runbooks, and the test evidence.

### Trust

- **Explicit trust only.** Each connection pins the IdP entity ID and its
  signing certificates, imported from administrator-provided metadata
  (`ParseIdentityProviderMetadata`), fetched from the IdP's metadata URL
  (`FetchIdentityProviderMetadata`, `MetadataSource`) or configured
  directly. Importing is the act of trust: a signature embedded in the
  metadata is not verified, and an aggregate (`EntitiesDescriptor`) is only
  accepted with a pinned entity ID.
  Nothing in a response extends that trust: the `Issuer` must equal the
  connection's entity ID, and a `KeyInfo` certificate only *selects* one of
  the trusted certificates (it must equal it exactly). A `KeyInfo` without
  certificate (a `KeyName` or `KeyValue` only, which Core §5.4.5 allows)
  selects nothing: it is cut from the verified bytes where no digest covers
  it, after both parsers agreed on its position, and the signature is then
  verified as one without `KeyInfo`.
- **What is verified is what is used.** gosaml2 and goxmldsig verify the
  signature and decode the identity from the verified canonical bytes; no
  identity data is read from the raw document, so a comment injected in a
  `NameID` (the CVE-2017-11427 class) cannot truncate it. Before
  verification, a structural profile pins the single `Assertion` as a child
  of the `Response`, unique `ID`s and the placement of every signature, so
  signature-wrapping attacks have nothing to wrap (see
  `TestCompleteLogin_XMLSignatureWrapping`).
- **No parser differential on attributes.** The pre-check reads the raw
  tree with etree, goxmldsig and gosaml2 decode with `encoding/xml`, and
  the two disagree on attributes that share a local name: etree's
  `SelectAttr` returns the first in document order whatever its prefix,
  `encoding/xml` the last, after exclusive C14N has reordered them. An
  element carrying two attributes of one local name — whatever their
  prefixes, namespace declarations included — and a prefixed attribute
  named like a SAML or XML-DSig attribute (`foo:Algorithm`,
  `foo:Destination`) are therefore refused, and the pre-check reads
  unprefixed attributes only. Without this, `Algorithm="…sha256"
  foo:Algorithm="…sha1"` passed the allowlist while goxmldsig digested with
  SHA-1. The `xml` prefix is bound to the XML namespace, which defines
  `xml:lang`, `xml:space`, `xml:base` and `xml:id` only: any other `xml:`
  attribute is refused, since `encoding/xml` matches attributes by local
  name and read `xml:NotBefore` as the `NotBefore` the pre-check never saw.
- **Signed Response or signed Assertion** (Profiles §4.1.3.5/§4.1.4.5 as
  amended by errata E93 and E26): a signed Response covers its single
  assertion. The SP metadata omits `WantAssertionsSigned`.
- **Algorithms.** goxmldsig accepts SHA-1, inclusive C14N and more; `samlsp`
  enforces its own allowlist on every signature before any cryptography:
  RSA or ECDSA with SHA-256/384/512, SHA-256/384/512 digests, and exactly the
  enveloped-signature and exclusive C14N transforms, in that order; no
  `ds:Object` (errata E91). SHA-1 (`rsa-sha1`, `ecdsa-sha1`, SHA-1 digests)
  is accepted only from a connection that sets `InsecureAllowSHA1`;
  inclusive C14N, HMAC and unknown algorithms never are. IdP keys are RSA of
  2048 to 8192 bits or ECDSA P-256/384/521. ECDSA signature values are
  verified as ASN.1 DER, as goxmldsig implements them: an IdP emitting the
  XML Signature 1.1 raw `r‖s` encoding fails closed. The SP signs its
  AuthnRequests with RSA (`rsa-sha256`).
- **Encrypted assertions are refused** (`ErrEncryptedAssertionUnsupported`)
  and the SP publishes no encryption key: TLS protects the assertion in
  transit, and gosaml2's decryption code — the subject of several advisories
  — is never reached.

### Ambiguous responses are refused

Some responses the schema allows are refused because two readers could
take different identities from them: several assertions, several
`SubjectConfirmation` or `AuthnStatement` elements, an assertion without
`NameID`, a Response without `Issuer`, or a condition the SP does not
understand (Core §2.5.1.1). Each refusal has a typed error. Configure the
IdP to send one assertion carrying a persistent NameID:

- **AD FS** sends no NameID unless a claim issuance rule of the relying
  party trust issues one: add a rule (for example *Transform an Incoming
  Claim*) whose outgoing claim type is *Name ID* with the *Persistent
  Identifier* format, from an immutable source such as `objectGUID`.
- **Microsoft Entra ID** — the *Unique User Identifier (Name ID)* claim
  defaults to the user principal name, which can be reassigned: prefer
  `user.objectid` with the persistent format.
- **Okta** — set the Name ID format to *Persistent* and the application
  username to an immutable value.
- **Keycloak** — set the client's Name ID format to `persistent` and enable
  *Force name ID format*; signing the documents, the assertions or both
  works (the pinned interoperability fixture signs both).
- **Google Workspace** — the custom SAML app sends the primary email with
  the *unspecified* format by default; set the Name ID format to
  *Persistent* and map the Name ID to an immutable attribute (an employee
  ID, for instance), since email addresses can be renamed and reassigned.
- **Shibboleth IdP** — it sends transient NameIDs unless a persistent
  NameID generator (computed or stored IDs, see `saml-nameid.properties`
  and `saml-nameid.xml`) is configured, and selects the format from the
  AuthnRequest's NameIDPolicy, the SP metadata and the relying party's
  `nameIDFormatPrecedence`. Without a persistent generator, a connection
  requesting the persistent format gets an error status
  (`InvalidNameIDPolicy`).

### Browser binding, CSRF and replay

- **Login CSRF by response injection.** `BeginLogin` binds the
  transaction to the browser with a `__Host-samlsp` cookie (`Secure`,
  `HttpOnly`, `Path=/`, no `Domain`): the prefix keeps sibling subdomains
  and network attackers from planting it. It is `SameSite=None` because the
  IdP's POST to the ACS is a cross-site navigation that would not carry a
  `Lax` or `Strict` cookie. A response is accepted only for the transaction
  of the same browser, and its signed `SubjectConfirmationData` must answer
  that transaction's request ID (errata E90). An attacker's own valid
  response posted into a victim's browser is therefore refused, whatever
  cookies a sibling host tossed (browser suite, BR3 and BR4). Some legacy
  browsers (Safari on iOS 12 and macOS 10.14, Chrome 51–66) mishandle
  `SameSite=None`: their logins fail with `ErrMissingBrowserBinding`.
- **The ACS must be exempt from the application's CSRF protection**: the
  POST comes from the IdP's page. The binding cookie and `InResponseTo` are
  its CSRF defense.
- **RelayState is never a URL.** It is a random handle; the return target
  stays server-side in `LoginOptions.AppState`, and the library never
  redirects. An application redirecting to its AppState after the login
  must accept local paths only, with an allowlist rather than a cleanup:
  one leading `/` and no `//`, RFC 3986 path and query characters only — no
  control character, white space, `\` or non-ASCII byte — and still a local
  path once percent-decoded. Browsers drop TAB, LF and CR inside a URL and
  read `\` as `/`: `/\t/evil.example` is `//evil.example`, another origin.
  `safeReturn` in `examples/saml-sp` implements this.
- **Unsolicited responses are refused**: IdP-initiated SSO cannot be bound
  to a browser (Profiles §4.1.5, errata E90).
- **Leaked in-flight requests.** The binding proves that the browser
  posting a response started the login, not that the IdP's page posted it.
  The IdP redirect URL carries the request ID (in `SAMLRequest`) and the
  RelayState handle: whoever learns it while the login is pending — browser
  history, a proxy or server log, a shared screen — can sign in at the IdP
  as herself, get the response to the victim's request and auto-post it
  from a page the victim visits; the victim's browser attaches its
  `SameSite=None` cookie and ends up signed in as the attacker. The same
  page can post a forged response that burns the victim's login (see
  *Single use*). `Connection.ResponseOrigins` (opt-in) closes both: the
  request's single `Origin` header (Fetch §3.2) — or, from a browser that
  sends none, its `Referer`'s origin — must be one of the IdP's origins,
  before the transaction is touched (`ErrOriginMismatch`). It is off by
  default because browsers send `Origin: null`, which an attacker's page
  can produce too and which is therefore refused, from a page whose
  Referrer-Policy is `no-referrer` (or `same-origin`, cross-origin), from a
  sandboxed page, and after any cross-origin redirect before the POST.
  Keycloak's default realm sends `Referrer-Policy: no-referrer` from its
  POST page; a realm header of `strict-origin-when-cross-origin` makes
  browsers send its origin (Keycloak live run, K8). Without the option, keep
  `TransactionTTL` as short as the IdP interaction allows, never log full
  IdP redirect URLs, and show the signed-in account after a login.
- **Single use.** `CompleteLogin` consumes the transaction atomically — one
  winner across instances — once the response passed the browser binding,
  the transaction checks, the status and the Response `InResponseTo`, and
  before any signature verification: a login allows one verification, and a
  response refused from then on ends it (`ErrTransactionConsumed` for any
  later POST; the span carries `samlsp.transaction_consumed`). Only the
  browser holding the binding cookie gets that far. The assertion then goes
  to the replay cache (Profiles §4.1.4.5), keyed by a digest of the
  connection, the issuer and the assertion ID and retained until the
  assertion can no longer be accepted (the earlier of
  `SubjectConfirmationData NotOnOrAfter` + skew and the transaction expiry,
  plus one minute). Both stores must be shared by every instance, and read
  from the primary.
- **Transaction integrity.** Each stored transaction carries an
  HMAC-SHA256 under a server-held key (`Config.TransactionKeys`, required)
  over its ID, browser binding, payload and expiry, verified in constant
  time before any stored field is used: a writer of the store can neither
  rebind a pending login to another browser or request nor relax its
  `ForceAuthn` or requested context (`ErrTransactionIntegrity`). The stores
  are trusted for availability and single consumption only: give the SP
  least-privilege access — a Redis ACL limited to its key prefix, a
  database user limited to its two tables. The keys are the records' only
  integrity protection: use keys distinct from the OpenID Connect client's
  and the session's, and replace a leaked one at once.
- **`BeginLogin` writes to the store without authentication**: rate-limit
  the login entry point, and the ACS per client too — a POST that passes
  the binding check costs one verification.
- **Gate login initiation.** A page of another site can send the user's
  browser to the login entry point (forced login initiation, a form of
  login CSRF): with an IdP session alive, the user is logged in, or
  switched to another session, without asking. Through a connection whose
  IdP the attacker controls, typically her own tenant, the victim ends up
  in the attacker's account. The browser binding cannot tell: the victim's
  browser started that login. Start logins only from same-origin
  navigations — Fetch Metadata's `Sec-Fetch-Site` is `same-origin` or
  `none` (typed URL, bookmark); refuse `cross-site` and `same-site` — or
  from a CSRF-protected POST. `examples/saml-sp` does the former and
  accepts requests without the header, so browsers older than Fetch
  Metadata keep working but stay exposed; a strict deployment refuses a
  missing header too. The browser suite (BR8) shows both
  ([guide](saml-sp.md#5-sessions-and-logout)).
- **The ACS location is checked** (Core §3.2.2, Bindings §3.5.5.2): the
  request must have been received at the connection's ACS URL — the same
  escaped path, the same host (`r.Host`, never a forwarding header), no
  query string — and `Destination` (required on a signed Response) and
  `Recipient` must equal it. Behind a proxy that rewrites `Host`, forward
  the original, or pass `CompleteLogin` a copy of the request whose `Host`
  comes from the trusted proxy's header. A
  Success `Response` must carry `InResponseTo`, equal to the request ID.

### Time

- `ClockSkew` (3 minutes by default, 5 at most; errata E92) applies to every
  bound: an assertion is valid from `NotBefore − skew` and until
  `NotOnOrAfter + skew`, exclusive. `IssueInstant`s must lie between the
  transaction start − skew and now + skew; `ForceAuthn` requires an
  `AuthnInstant` after the transaction start − skew.
- goxmldsig checks the IdP certificate validity with gosaml2's single
  clock, which `samlsp` sets to `now − ClockSkew` so that gosaml2's own time
  checks are never stricter than those of `samlsp`. An IdP certificate is therefore
  accepted until `NotAfter + skew`, but only from `NotBefore + skew`: a
  certificate whose validity starts at a key rollover is refused during the
  first `ClockSkew`. Import new IdP certificates ahead of their use (errata
  E68: any listed key may sign).

### Identity

The IdP entity ID is a claim of the connection, not a global identity: in a
multi-tenant application, one tenant can configure an IdP whose entity ID
collides with another tenant's. Key external accounts on the connection ID
and the persistent NameID (with the issuer and the NameID qualifiers).
Never key them on a transient NameID or an email attribute, and never link
accounts by email automatically: an IdP vouching for an address says nothing
about the account another tenant's IdP vouches for. Encode the key without
ambiguity — a connection ID may contain any separator: `examples/saml-sp`
length-prefixes the connection ID, the issuer, the NameID qualifiers (absent
ones stand for the issuer and the SP entity ID), the format and the value.

### Resource limits

`MaxResponseSize` (256 KiB by default, 16 KiB to 1 MiB) bounds the ACS
request body — or, when the application parsed the form before calling
`CompleteLogin` (Go's own limit is 10 MB), the SAMLResponse value itself.
The response then passes a streaming lexical gate before anything builds a
tree: at most 1 MiB, 450
elements (`MaxResponseElements`, sized from goxmldsig's 1000-node
canonicalization budget; gosaml2 verifies up to about 500), 4096 tokens,
depth 64, 16 attributes and 16 namespace declarations per element, 32
in-scope prefixes, 8 KiB attribute values; no DTD, entity or processing
instruction, and only namespace-well-formed names (Namespaces in XML 1.0
§3, §7: no empty prefix or local part, which encoding/xml would keep whole
in no namespace). Measured on an Apple M-series machine (Go 1.26): a typical
login costs about 1.1 ms and 1.1 MB; the most expensive response within the
default limits about 25–33 ms and 21–28 MiB, about 61–69 ms and 33–43 MiB at
the 1 MiB ceiling; inputs aimed at amplification are refused within 10 ms
and 9 MiB. When a signature carries no KeyInfo and the connection trusts
several certificates, each certificate tried re-runs the whole verification:
at most the three most recent valid ones are tried, the one that verified
the connection's last such signature first, which bounds that case to three
times the costs above — once per login, since the transaction is consumed
before the verification. The pre-check runs twice on a response whose
certificate-less `KeyInfo` it cuts, within the same limits and before any
store access. A response carrying hundreds of group
memberships exceeds the element cap (`ErrResponseTooLarge`): filter the
groups the IdP releases to the application rather than raising limits.

### Metadata retrieval

`FetchIdentityProviderMetadata` downloads an IdP's metadata once, and a
`MetadataSource` keeps it current for a `ConnectionResolver`. Both treat the
network as hostile:

- **The URL is configuration** — the application's, or a tenant
  administrator's — and never a value read from a SAML message or a
  request. It must be https (http only with `Outbound.AllowHTTP`), without
  credentials or fragment. No response content triggers a fetch: an
  unknown `KeyInfo` certificate fails the login, it does not refresh the
  metadata, so an attacker cannot make the SP fetch.
- **Requests go through `outbound`** (see
  [Outbound requests](#outbound-requests-ssrf)): publicly routable
  destinations only, judged on the address dialed, no redirect, no proxy,
  no cookie, no credentials, 10 s, and the smaller of `MaxSize` (1 MiB) and
  the policy's body limit, counted after decompression. When the policy
  allows redirects, none may leave the configured URL's origin (scheme,
  host and port): keys can only come from that origin. A host or port that
  `outbound` always refuses (`127.1`, a trailing dot, an underscore, port
  0) fails at construction with `ErrInvalidConfig`. Only a 200 answer is
  read; no error carries the response body. An on-premises IdP needs its
  subnet in `Outbound.AllowedPrefixes`; pin its host in `CheckURL`, and its
  private CA in `RootCAs`.
- **Trust** rests on TLS to the configured origin and on the pinned entity
  ID (`MetadataSourceConfig.EntityID` is required): a document of another
  entity is refused. `FetchOptions.EntityID` is optional, to discover a new
  IdP's entity ID: pin it whenever a fetch replaces keys already
  configured. Keys and endpoints change only through a valid
  document of that entity fetched from that URL, so an IdP key rollover is
  picked up at the next refresh — announce the new key in the metadata
  before signing with it. Signed metadata is not supported: the embedded
  signature is ignored, and a federation aggregate, whose trust comes from
  its signature, must not be used as a source. Where TLS to the IdP's
  metadata host is not trusted enough, import the metadata out of band.
- **Bounded refresh**: at the document's `cacheDuration` (one hour when
  absent, the shortest interval for `PT0S`) clamped to `[MinRefresh,
  MaxRefresh]` (5 minutes, 24 hours by default), and when it expires;
  concurrent callers share one fetch, which runs detached from the caller
  that started it and is bounded by the outbound timeout; fetches are
  spaced by `RetryInterval` (one minute) after a failure or an early
  expiry. A due refresh never delays a login while a usable document is
  cached: it runs in the background, and only a caller with nothing usable
  waits for it, so a slow or hostile metadata endpoint cannot put its
  latency on the login path. While refreshes fail, the last good
  document is served for at most `MaxStale` (7 days) after it was fetched
  and never past its `validUntil` (Metadata §4.3.2, errata E94); then
  logins fail closed with `ErrMetadataExpired`. Failures surface as
  `ErrMetadataUnavailable` (the `outbound` errors stay matchable),
  `ErrInvalidMetadata` or `ErrMetadataExpired`; a resolver returning them
  makes `BeginLogin` and `CompleteLogin` fail as infrastructure errors, not
  rejections.

### Dependencies

XML signature verification and canonicalization are never implemented in
this repository. They come from:

| Module | Minimum | Advisories considered |
| ------ | ------- | --------------------- |
| `github.com/russellhaering/goxmldsig` | v1.6.1 | GHSA-479m-364c-43vc (CVE-2026-33487, signature bypass, fixed in v1.6.0); GHSA-qhrp-hfff-vphr (quadratic memory in SignedInfo canonicalization, fixed in v1.6.1); older bypasses (CVE-2020-15216) |
| `github.com/russellhaering/gosaml2` | v0.12.0 | GHSA-66r8-42f7-4q74 (allocation amplification in the round-trip validation, fixed in v0.12.0); GHSA-5hj8-q7fv-qrj6 and GHSA-hwqm-qvj9-4jr2 (decryption panics: unreachable, encrypted content is refused first); GHSA-pcgw-qcv5-h8ch and GHSA-vv4x-5gvr-chh8 (unsigned logout messages: Single Logout is not used); GHSA-6gc3-crp7-25w5 (CVE-2023-26483, DEFLATE bomb: POST bodies are never inflated, and gosaml2's own limit is set to one byte) |
| `github.com/beevik/etree` | v1.8.1 | GHSA-qm2r-qg5g-crr3 (stack overflow on deep nesting, also bounded by the depth cap), GHSA-2mj8-7fmf-pr7x, GHSA-f965-f62m-c42m, GHSA-x27v-cqwr-28jx — all fixed by v1.7.1 |
| `github.com/mattermost/xml-roundtrip-validator` | v0.1.0 | none (used by gosaml2 to refuse documents `encoding/xml` does not round-trip) |

gosaml2 is maintained, verifies before it decodes, and decodes from the
verified bytes; `samlsp` uses it only to encode AuthnRequests and to verify
responses, never its `RetrieveAssertionInfo` (which reports audience and
time problems as warnings). `github.com/crewjam/saml` was not chosen: it had
critical signature bypasses (CVE-2020-27846, and CVE-2022-41912 with several
assertions) and is less actively maintained; it serves only as the
independent IdP of the private interoperability tests. A future goxmldsig or
gosaml2 upgrade must keep `TestGosaml2TraversalBudgetIsPinned` green: the
element cap depends on goxmldsig's traversal budget.

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
- **Cookie only** — the `Manager` reads the session from the request's
  `Cookie` header field, through `httpsec.Carrier.CookiesNamed`, never from
  the URL nor from a header named like the cookie: a link carrying a session
  value cannot log a browser into another account.
- **Session fixation** — `Manager.Rotate` mints a fresh session ID; call it
  immediately after a privilege change (login). The ID never appears raw in
  a span — only a SHA-256 fingerprint.
- **CSRF** — the synchronizer-token helper (`CSRFToken` / `VerifyCSRF`)
  compares tokens in constant time. The session cookie being `HttpOnly`
  keeps the token out of reach of XSS.
- **Size** — the whole session is JSON-encoded into the cookie; browsers
  cap a cookie near 4 KiB. Keep `Values` small.

## OpenID Connect client

`oidc/client` logs users in through external OpenID Providers. The
provider is trusted for what it asserts about its own users only; the
callback request, the browser and — in a SaaS — the provider's metadata
are attacker-influenced.

- **Browser binding** — a login is bound to the user agent that started
  it: `Begin` draws a 256-bit binding secret the user agent keeps (an
  HttpOnly `__Host-` cookie with `StartLogin`), and the callback must
  present it. The nonce and the PKCE verifier are HMAC-SHA256 values of
  that secret (OpenID Connect Core §15.5.2), so the transaction store holds
  only a hash of the state and of the binding: reading the store yields
  nothing that completes a login, and a stolen state alone cannot be
  replayed from another browser (login CSRF, RFC 9700 §4.7).
- **Store integrity** — every transaction carries an integrity MAC over all
  its fields, which `Complete` verifies before using any stored field: a
  transaction altered in the store — a stripped `max_age` or `acr_values`,
  a rewritten `AppState` or redirect URI — fails its login
  (`ErrTransactionIntegrity`). The MAC key is
  HMAC-SHA256(transaction key, `"oidcclient/integrity/v2"` ‖ binding
  secret): it needs both the binding secret — which the user agent of the
  login holds — and a server-held transaction key
  (`Config.TransactionKeys`) the store never sees, so an attacker who can
  write to the store cannot forge it even for a login it runs with its own
  browser. The store is trusted for availability and single consumption
  only. The transaction keys are secrets like a session key: 32 bytes or
  more from a cryptographic source, shared by every instance serving
  callbacks, never logged (`Config` and `*Client` redact them with every
  `fmt` verb and in `slog`). Rotate them in three steps — add the new key last on every
  instance, move it first, remove the old one once `TransactionTTL` has
  elapsed: the first key protects new transactions, every key is accepted.
- **Single use** — `TransactionStore.Consume` removes the transaction
  atomically, unknown first, then expired whatever the binding, then a
  binding mismatch, which keeps the transaction so that a leaked state
  cannot burn the victim's login. A replayed callback finds nothing and
  never reaches the token endpoint.
- **Mix-up attacks** (RFC 9700 §4.4) — give every connection its own
  redirect URI, distinct from every other connection's (by scheme, host,
  port, path or query parameter): `Complete` refuses a response received on
  another URL than the connection's redirect URI, and a transaction of
  another connection, issuer, client, redirect URI or response mode. A
  provider advertising RFC 9207 must also send the `iss` parameter,
  compared with its issuer. Never route callbacks by the state value.
  Distinct redirect URIs leave the gap RFC 9700 §4.4.2.2 names — an
  attacker registering, at the honest provider, a client with the redirect
  URI of its own connection; RFC 9207 closes it, so prefer providers that
  support it. Behind a reverse proxy, `HandleCallback` compares the Host
  header the proxy forwards: preserve it, or give `Complete` the public
  URL.
- **ID Token** — validated per OpenID Connect Core §3.1.3.7 before anything
  is returned: asymmetric algorithms only (HMAC and `none` refused), `typ`
  absent or `JWT` (an RFC 9068 `at+jwt` access token is refused), keys from
  the configured issuer's `jwks_uri` only (`jku`, `x5u`, `jwk`, `x5c`
  ignored) through a bounded cache that refetches once, rate limited, for
  an unknown key, and never on a bad signature from a known one; `iss`,
  `aud` (further audiences only when trusted), `azp`, `exp`/`iat`/`nbf`
  within a bounded skew, `nonce`, `auth_time` against `max_age`, `acr`
  against the requested `acr_values`, and `at_hash` when present. Every
  JSON document is decoded strictly: duplicate member names, two names
  that differ only by case, invalid UTF-8 and unpaired surrogates are
  refused, so no decoder can pick between two members. A lone member whose
  name differs from a known claim only by case (`EMAIL_VERIFIED`) is
  another claim, which OpenID Connect Core §2 and RFC 7519 §4 require
  ignoring — yet `encoding/json`, matching struct fields
  case-insensitively, reads it as `email_verified`. An honest provider
  releasing attribute names its users choose can emit one. Decode claims with
  `Identity.DecodeClaims` / `UserInfo.Decode` or into a map, and read the
  validated values (`Subject`, `Audience`, `AuthTime`, `ACR`, `AMR`) from
  the `Identity` fields, never again from `Claims`.
- **Identity** — the verified identity is the issuer and subject pair
  (Core §5.7). Link accounts on (connection or tenant, issuer, subject);
  never on email, phone or username, which another subject or provider can
  assert. For Microsoft Entra ID, configure the tenant's own issuer: the
  templated multi-tenant issuers are refused.
- **Cookies** — binding cookies are `__Host-` (Secure, Path=/, no Domain:
  a sibling subdomain cannot plant one), HttpOnly, named after the state so
  parallel logins coexist, capped at four per browser, and deleted by the
  callback. The cap counts and expires only names of their shape — the
  prefix and 16 lowercase hex digits — never the application's own cookies
  sharing the prefix. SameSite is Lax for the `query` response mode — the callback
  is a top-level GET — and None for `form_post`, whose cross-site POST
  carries no Lax cookie; an opt-in headless-Chrome test checks both.
  `InsecureCookies` drops Secure for local http development only, and is
  refused with `form_post`.
- **CSRF** — exempt the callback route from CSRF middleware in `form_post`
  mode: the cross-site POST is the protocol, the binding cookie its
  defense. Start logins on a user action from the application's own
  origin (a POST behind `http.CrossOriginProtection` or a CSRF token) and
  rate limit them: each start writes a transaction, and a non-browser
  client passes the cross-origin protection. `examples/oidc-client` limits
  each client (an IPv4 address, an IPv6 /64) and each network (an IPv4
  /24, an IPv6 /48) and bounds its in-memory store (`memory.WithCapacity`);
  a flood from enough networks still fills the store, which refuses new
  logins until transactions expire — limit at the edge as well.
- **Redirect targets** — `AppState` comes back from the store verbatim;
  validate it before using it as a redirect target. After a successful
  callback, create a fresh session and answer 303 to a clean URL, so the
  code leaves the browser history (RFC 9700 §4.3.1).
- **Account linking** — linking an external identity to an account that
  is already signed in is a login started on the victim's behalf if it can
  be forged: on a hostile tenant's connection, a forged link start would
  silently attach the attacker's identity to the victim's account. Start a
  link only with a CSRF-protected POST after a recent re-authentication,
  put a random value bound to the local session in `AppState`, and after
  `Complete` link only when it matches the current session's value — never
  link on an identity whose `AppState` does not prove the link was started
  by that session.
- **Provider errors** — `AuthorizationError` and `TokenError` carry the
  provider's `error`, `error_description` and `error_uri`: untrusted text,
  their `Error()` prints the code only. Never render the description or the
  URI. The errors of `New` (discovery) may name the resolved address of an
  allowed destination: when tenants configure issuers, log them and show a
  generic message. The provider-controlled text an error echoes (an issuer,
  a media type, a redirect target, a JOSE header member, a query parameter
  name, the debug data of an HTTP/2 GOAWAY ending a response) is Go-quoted
  — control characters and invalid UTF-8 escaped — then cut to about 256
  bytes.
- **Tokens** — token and UserInfo requests never follow redirects
  (discovery and JWK Set requests only within the origin requested);
  `UserInfo` sends an identity's access token only to the UserInfo
  endpoint of the connection that issued it, and returns claims only when
  their `sub` is the identity's. Every `fmt` verb and `slog` redact
  secrets (`%p` of a non-pointer value excepted: fmt prints the fields
  before any method), and so does `encoding/json` for `Config`,
  `AuthRequest` and `Callback` — which matters to `slog`'s JSON handler,
  which encodes a nested value with `encoding/json`. `Identity` and
  `Tokens` deliberately encode their tokens (applications persist them),
  `UserInfo` its claims: never log them nested in another value.
- **Caveats** — sending `acr_values` makes `acr` required, among the
  requested values; a public client (`none`) requires the provider to
  advertise S256. `github.com/coreos/go-oidc` was evaluated and rejected:
  its verifier skips nonce, azp, iat, `typ`, auth_time and acr, and its key
  set refetches on every failure without rate limit (see the package
  documentation of `oidc/client`).

## OpenID Connect: protocol validation vs application policy

`oidc/provider` and `oidc/client` validate the protocol — every rule their
feature matrices list ([oidc-provider.md](oidc-provider.md),
[oidc-client.md](oidc-client.md), [oidc-conformance.md](oidc-conformance.md)).
What the protocol leaves open is policy, and stays with the application:

| Concern                    | The library validates                                                                                                    | The application decides                                                                                      |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------ |
| Tenants and connections    | issuer equality, a transaction bound to its connection, issuer, client and redirect URI, RFC 9207 `iss`; realms and issuer-bound clients (provider) | which connections exist, routing a login start to one, distinct redirect URIs, which issuers tenants may configure |
| Identity and accounts      | the (issuer, subject) pair, UserInfo `sub` equality                                                                      | account linking (on connection, issuer, subject), just-in-time provisioning, link flows bound to a session    |
| Authentication strength    | `max_age`/`auth_time`, `acr` among `acr_values` (client); freshness, essential `acr` (provider)                          | the acr levels required, step-up and MFA, AMR policy, the login pages                                         |
| Consent                    | released claims, a scope that only narrows, `offline_access` only with `prompt=consent` or the application's policy      | the consent pages and records, the offline-access policy                                                      |
| Sessions                   | no session of another realm or end-user, no state revealed under `prompt=none`                                           | session lifetime, a fresh session after each login, sign-out (no logout specification is supported)          |
| Account disabling          | `ErrUnknownSubject` stops every grant at its next use (exchange, refresh, UserInfo)                                     | disabling accounts, revoking their token families for immediate effect                                        |
| Keys                       | rings validated on every use, public keys only published; the client's bounded JWK Set cache                             | key custody (KMS), the rotation schedule, the response to a leaked key                                       |
| Outbound requests          | https and public destinations only by default                                                                            | exemptions for on-premises providers (`AllowedPrefixes`, `CheckURL`, `RootCAs`)                               |
| Login transactions         | browser binding, integrity, single use                                                                                   | the store's deployment, the transaction keys (generation, sharing, rotation), purging                        |
| Abuse and audit            | nothing beyond the protocol's refusals                                                                                   | rate limiting of login starts and endpoints, audit logs (`OnError` sinks), monitoring                         |

## Outbound requests (SSRF)

Modules that fetch URLs from configuration or remote metadata (OpenID
Connect discovery, JWK Sets, token and UserInfo endpoints, SAML metadata)
use `outbound.NewClient`. In a multi-tenant deployment those URLs are
attacker-influenced — a tenant administrator types an issuer, a discovery
document names its own endpoints — so the client defends the server's own
network:

- **Destinations** are judged on the address actually connected to, in
  `net.Dialer.ControlContext`, after DNS resolution: a name that resolves
  to a public address when vetted and to an internal one when dialed (DNS
  rebinding) is still refused. Refused by default: loopback, private
  (RFC 1918, RFC 4193 unique-local), shared (RFC 6598, CGNAT), link-local
  (including `169.254.169.254` and the other cloud metadata endpoints),
  multicast, unspecified, reserved, documentation and benchmarking space,
  and any scoped (zoned) address. IPv4-mapped IPv6 addresses and NAT64
  (`64:ff9b::/96`) addresses are judged on the IPv4 address they reach;
  IPv6 is limited to `2000::/3` minus its special-purpose blocks (Teredo,
  6to4, documentation), so an unknown or future reservation is refused.
- **URLs** must be https (http only with `AllowHTTP`, for development), carry
  no userinfo, and name an ASCII host: non-ASCII names (which `net/http`
  would map to another name before dialing), percent-encoded or
  underscore characters, empty labels and trailing dots are refused, so a
  host check in `CheckURL` sees the name actually dialed.
- **Redirects** are not followed unless `MaxRedirects` allows it; every
  hop is re-checked, and https→http is always refused. Credential-bearing
  requests (token, UserInfo) never follow redirects. `oidc/client`'s
  discovery and JWK Set requests and `saml/sp`'s metadata requests, whose
  answers are trusted because of the origin they come from, never follow
  a redirect to another origin (scheme, host and port), whatever
  `MaxRedirects` allows: after such a hop another server would only have
  to write the expected issuer to get its keys trusted.
- **Resources** are bounded: one timeout for the whole exchange (10 s by
  default), a size cap on every body (1 MiB by default) counted after
  transparent decompression — a gzip bomb fails — and a 64 KiB header cap.
- **No ambient authority**: no proxy (an environment proxy would be
  judged instead of the destination), no cookie jar, TLS 1.2 or later with
  verified certificates.

Exemptions are explicit: `AllowedPrefixes` for an on-premises identity
provider's subnet (or `outbound.LoopbackPrefixes()` in tests). Any port
is allowed by default; restrict ports and hosts in `CheckURL`, and deny
specific public addresses in `CheckAddr`. Only the well-known NAT64 prefix
is decoded: on a network translating a network-specific prefix (RFC 6052),
refuse that prefix in `CheckAddr`, or its addresses reach the private IPv4
addresses they embed.

Host names ending in a number (`127.1`, `2130706433`, `0x7f.1`) are refused
before `CheckURL`: resolvers read them as IPv4 addresses, so a host check
would vet another name than the one dialed. A refused destination is never
named in an error, but the errors of allowed destinations may name their
resolved address and port, and every error tells whether a name is
refused: when tenants supply URLs ("test this connection"), log the error
and show them a generic message, or the error text becomes an oracle on
the internal network.

## Credentials in header fields only

`httpsec.Carrier.Get`/`Values` (and the gRPC and ConnectRPC carriers) read
header fields only: the Basic and Bearer extractors accept credentials from
the `Authorization` field alone, never from the URL query string (RFC 6750
§5.3: tokens in URLs leak through logs, `Referer` and browser history) nor
from a cookie named like the field (an ambient credential a cross-site
request would carry).

## Extractor order

The `Engine` tries its extractors in order and the first one that finds a
credential wins (as in Spring Security's filter chain): a deliberate design,
not a fallback between schemes. Put the header-based extractors (bearer,
basic) before the session extractor: a browser attaches cookies to
cross-site requests by itself — `SameSite=Lax` still sends them on
top-level GET navigations — but never an `Authorization` header, so an
engine that accepts a cookie session authenticates requests an attacker's
page can trigger. Protect every state-changing endpoint reached with a
cookie session against CSRF, and prefer one engine per audience (browser
pages, APIs) so that an API never authenticates an ambient cookie.

## Authorization

Authorization follows Spring Security's voter model, and fails closed:

- **The attributes are the policy.** Each voter votes only on the
  attributes whose family and value it supports: `HasRole("ADMIN")` votes
  on `security.Role("ADMIN")` and abstains on `security.Role("USER")`, so a
  decision manager shared by several routes grants each route only what it
  asks for. `voter.Authenticated()` and `voter.Anonymous()` vote only on
  `security.IsAuthenticated` / `security.IsAnonymous`: list the state you
  require among the route's attributes.
- **Separate namespaces.** A role is the authority `ROLE_<name>`
  (`security.RolePrefix`), a scope the authority `scope:<name>`
  (`security.ScopePrefix`, one scope per authority), anything else a plain
  authority matched verbatim by `HasAuthority`: a scope a client obtained
  can never pass for a role.
- **No requirement is ignored.** A decision is denied when one of its
  attributes is supported by no voter of the decision manager, when there
  is no attribute, and when there is no voter — whatever the strategy, the
  tie-break and the abstain fallback: `WithAbstainFallback` only decides
  for custom voters that support an attribute and abstain.
- **Composites.** `voter.And` grants only when every inner voter grants — an
  inner voter whose attribute the route does not list makes it deny, so list
  one attribute per inner requirement. `voter.Not` never turns the refusal
  of an unauthenticated principal into a grant: `Not(HasRole("BANNED"))`
  admits authenticated principals without the role, not anonymous callers.
  A `Role("X")` attribute is decided by every voter that supports it,
  negated ones included: a decision manager holding `Not(HasRole("X"))`
  grants a `[Role("X")]` route to the authenticated principals *without*
  X, and next to a positive `HasRole("X")` voter the affirmative strategy
  grants it to those *with* X too. Keep a negated policy in its own
  decision manager, used only by the routes it was written for.
- **Strategies.** Affirmative grants on one satisfied attribute (OR);
  unanimous requires every voting voter to grant (AND across voters), but a
  multi-name voter such as `HasAnyRole` grants when the principal holds any
  of the requested names — use one voter per role, or `voter.And`, for an
  AND of roles.

## Transport error mapping

Error mappers return terse, code-first responses, classified once by
`security.ErrorClass` — joined errors included — so a refusal by one
authenticator is never masked by another one's lack of support, and an
outage never reads as a verdict on the credentials:

| Class | HTTP | `WWW-Authenticate` (scheme S, realm R) | gRPC / ConnectRPC |
| --- | --- | --- | --- |
| `invalid_request` (e.g. repeated `Authorization`) | 400 | Bearer: `Bearer realm=R`; + bearer token sent: `error="invalid_request"` | `InvalidArgument` |
| `unavailable` (`ErrUnavailable`) | 503 | Bearer: `Bearer realm=R` | `Unavailable` |
| `token_expired`, `token_not_found`, `client_secret_mismatch`, `invalid_credentials` | 401 | `S realm=R`; Bearer + bearer token sent: `error="invalid_token"` (RFC 9068 §4) | `Unauthenticated` |
| `authentication_required`, `unsupported_credential` | 401 | `S realm=R` — no error code (RFC 6750 §3.1) | `Unauthenticated` |
| `insufficient_scope`, `access_denied` | 403 | `S realm=R`; Bearer + bearer token sent: `error="insufficient_scope"` | `PermissionDenied` |
| `no_extractor`, `_OTHER` (no sentinel: a broken contract) | 500 | Bearer: `Bearer realm=R` | `Internal` |

A ConnectRPC error travels over HTTP with the status of the HTTP column, and
the `connectrpcsec` default mapper puts the same `WWW-Authenticate`
challenge in its metadata — sent as response headers on unary calls — so
every Connect 401 carries one.

Every 401 carries a challenge with a realm (`api` by default; RFC 9110
§11.6.1, RFC 7617 §2, RFC 6750 §3), a Basic one also `charset="UTF-8"`
(RFC 7617 §2.1), and the realm is sent as an RFC 9110 quoted-string — a
realm a quoted-string cannot carry is refused at startup. A Bearer resource
challenges every refusal, 400 and 5xx included: RFC 6750 §3 requires the
challenge whenever the request carried no access token that enables
access. An unauthenticated
principal refused by `httpsec.Authorize` is asked to authenticate (401), an
authenticated one refused (403) (RFC 9110 §15.5.2, §15.5.4); `Authorize`
answers with the challenge of the `Middleware` in front of it. The RFC 6750
error codes are sent only when the request carried a bearer token. The
`error_description` is a fixed string per code: the response never says why
authentication failed. Clients are expected to branch on the status and the
code, not parse the message. The gRPC messages are one fixed string per
code (`unauthenticated`, `permission denied`, …). gRPC clients commonly
retry `Unavailable`: wrap `security.ErrUnavailable` only for a transient
dependency failure.

Install the gRPC interceptors for both RPC kinds — `grpcsec.ServerOptions`
and `grpcsec.AuthorizeServerOptions` return the unary and stream chains
together: chaining only unary interceptors leaves every streaming RPC (the
health service's `Watch`, server reflection, your own streams)
unauthenticated.

## Observability

No secret is ever placed on a span attribute or log line, and the core
spans record the class of an error (`security.ErrorClass`), never its text,
which can hold user input such as a typed username. See
[observability.md](observability.md) for the secrets policy and the full
span catalog.

## Toolchain and supply chain

- **Go toolchain.** Every module requires Go 1.27.2 (its `go` line). The
  library cannot be built with a toolchain carrying the standard-library
  advisories fixed up to go1.27.2: HTTP/2 server crashes and request
  smuggling in `net/http`, `crypto/tls`, `encoding/asn1`, `net/url`,
  `encoding/xml`. Build and ship with the latest Go patch release, and run
  `govulncheck` on your application: which advisories matter depends on the
  code you call.
- **Vulnerability scanning.** The `govulncheck` workflow scans every module
  outside the workspace (its own requirements, tests included) on every
  change and weekly, and it must be green on the commit of a release; the
  release workflow also scans the released module itself and never
  publishes over an advisory reachable from it. Known and not reachable:
  GO-2026-5932 (`golang.org/x/crypto/openpgp` is unmaintained, no fix) is
  reported at module level for the modules that require
  `golang.org/x/crypto`; none imports `openpgp`. Accepted reachable
  advisories (ID, reason, owner, review date): none.
- **Dependencies.** Dependabot proposes version updates for every module
  after a 7-day cooldown (security updates are not delayed). The
  development tools (golangci-lint, govulncheck, goveralls, mockery) are
  pinned in modules of their own under `tools/` and never reach a library's
  module graph.
- **CI and releases.**
  - The workflows run with a read-only token by default (only the release
    publish job gets `contents: write`), every action is pinned to a full
    commit SHA, and checkouts keep no credentials.
  - A release is verified with a read-only token (`scripts/release-check.sh`,
    build, test, lint, govulncheck) before a separate job publishes the
    GitHub release, without checkout or third-party code.
  - Module tags are not signed: verify the modules through the Go checksum
    database (`sum.golang.org`), as `go get` does by default. Never set
    `GOSUMDB=off`, and never let a `GOPRIVATE` or `GONOSUMDB` pattern match
    `github.com/hyperscale-stack/*` (`GOINSECURE` and `GONOPROXY` do not
    affect checksum verification).

## Operator checklist

- [ ] Build with Go 1.27.2 or later, the latest patch release, and run
      `govulncheck` on your application.
- [ ] Pick a password hasher and review its cost against current hardware.
- [ ] Rotate JWT signing keys; expose them through a JWKS endpoint
      (`oidc/provider` serves one).
- [ ] Keep the JWT allowlist asymmetric unless you truly need HMAC.
- [ ] Use `Profile20BCP` or stricter; do not enable the `implicit` /
      `password` legacy grants without a documented reason.
- [ ] Give every confidential client that authenticates with a secret a
      high-entropy one. Register a client that cannot keep a secret as
      public (`none` + PKCE). Declare every client's `GrantTypeValues` and
      `ScopeValues` — an empty list allows nothing — and watch `OnError`
      for `ErrNoGrantTypesDeclared` / `ErrNoScopesDeclared` after an
      upgrade.
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
- [ ] Bound refresh-token families with `grant.Config.RefreshFamilyTTL` —
      the longest session you accept, 30 days for instance — so a stolen
      refresh token kept alive by rotation dies with its family.
- [ ] Make the `IssuerResolver` return the same issuer for every endpoint
      of a realm (`/authorize`, `/token`, `/revoke`, `/introspect`), and
      authenticate users within `AuthorizeRequest.Issuer` in the
      `ConsentFunc`. With several issuers and one `ClientStore`, register
      every client at its issuers (`IssuerBoundClient`,
      `DefaultClient.IssuerValues`) or scope the store by issuer.
- [ ] With `store/sql`, apply the `ALTER TABLE` statements of each release
      (MIGRATION.md) before deploying it; keep PostgreSQL databases in
      `UTF8` and MySQL tables in `utf8mb4` with a strict `sql_mode` — a
      non-strict MySQL truncates an over-long value instead of refusing it.
- [ ] With `oidc/provider`: an https issuer the `IssuerResolver` never takes
      from an unvalidated `Host`; a `KeySource` backed by your key store,
      rotated through `KeyRing.Published` (publish, sign, retire once the ID
      Tokens it signed have expired); access-token audiences that are never
      client IDs; `RefreshTokenScope = offline_access`; sessions scoped to
      their realm (and tenant), and clients to their issuers
      (`IssuerBoundClient`); CSRF tokens and anti-framing headers on the
      login and consent pages; `ErrUnknownSubject` from the `ClaimsSource`
      for disabled end-users, whose token families you also revoke.
- [ ] Serve over HTTPS so `Secure` cookies and bearer tokens are protected.
- [ ] Supply at least two session keys so rotation is possible without
      invalidating live sessions.
- [ ] SAML: import IdP metadata through a trusted channel, or fetch it from
      the IdP's https metadata URL with a `MetadataSource` pinned to its
      entity ID; never take a metadata URL from a request. Widen the
      outbound policy only for an on-premises IdP (`AllowedPrefixes`,
      `CheckURL`, `RootCAs`). Enable `InsecureAllowSHA1` only for an IdP
      that cannot do better, with a plan to remove it.
- [ ] SAML: share the transaction store and the replay cache between
      instances (`saml/sp/store/sql` or `saml/sp/store/redis`) and purge
      expired SQL rows. Give the SP least-privilege access to them: a Redis
      ACL limited to its key prefix, a database user limited to its two
      tables.
- [ ] SAML: load `samlsp.Config.TransactionKeys` from your secret store —
      the same keys on every instance, distinct from the OpenID Connect
      client's and the session keys — and rotate them by adding the new key
      last, then moving it first, then removing the old one after
      `TransactionTTL`; replace a leaked key at once.
- [ ] SAML: exempt the ACS routes from CSRF protection, start logins only
      from a same-origin gesture (a POST with a CSRF token, or
      `Sec-Fetch-Site` `same-origin` or `none`), rate-limit the login entry
      point and the ACS per client, serve the login on the ACS host, and
      key accounts on the connection and the persistent NameID — never on
      an email.
- [ ] SAML: let the ACS see the host the browser used: forward the
      original `Host` at the proxy, or pass `CompleteLogin` a copy of the
      request whose `Host` comes from your trusted proxy's header.
- [ ] SAML: set `Connection.ResponseOrigins` to the IdP page's origin when
      that page lets browsers send it (a Keycloak realm needs its
      Referrer-Policy header changed first); otherwise keep `TransactionTTL`
      short and never log full IdP redirect URLs.
- [ ] Install an OpenTelemetry `TracerProvider` to collect the spans.
- [ ] Give every route the attributes its voters check, and a voter for each
      attribute (an unsupported one denies); require a logged-in caller
      with `security.IsAuthenticated`, and store roles as `ROLE_<name>`
      and scopes as one `scope:<name>` authority each.
- [ ] Set the challenge scheme of each HTTP / ConnectRPC adapter to the
      scheme its extractors accept, with a printable-ASCII realm.
- [ ] On gRPC, install the authentication and authorization interceptors
      for both RPC kinds (`grpcsec.ServerOptions`,
      `grpcsec.AuthorizeServerOptions`).
- [ ] In your authenticators, wrap `security.ErrUnavailable` for a
      dependency that is temporarily down, a credential sentinel for a
      refusal — never a plain error.
- [ ] Keep the zero `outbound.Policy` in production; exempt only the exact
      subnets of on-premises identity providers in `AllowedPrefixes`, and
      restrict hosts and ports in `CheckURL` when tenants configure URLs.
- [ ] Give every OpenID Connect connection its own redirect URI
      (`/oidc/{connection}/callback`), registered exactly at its provider.
- [ ] Use a shared `TransactionStore` (`oidc/client/store/sql` or
      `store/redis`) when several instances serve callbacks, and schedule
      `PurgeExpired` with the SQL store.
- [ ] Load `oidcclient.Config.TransactionKeys` from your secret store — the
      same keys on every instance — and rotate them by adding the new key
      last, then moving it first, then removing the old one after
      `TransactionTTL`.
- [ ] Link accounts on (connection, issuer, subject), never on email;
      create a fresh session after each login.
- [ ] Start logins with a same-origin POST and rate limit them; exempt only
      the `form_post` callback routes from CSRF middleware.
- [ ] Rotate an OpenID Provider's keys on its relying parties' timetable:
      publish the next key at least an hour before it signs; after a leak,
      withdraw the key and ask relying parties to rebuild their clients
      (`oidc/client` keeps a withdrawn key for up to an hour).
- [ ] Prefer providers that send the RFC 9207 `iss` parameter; never
      register a connection's redirect URI at another provider.
- [ ] Serialize the refreshes of one grant across instances: providers
      that rotate refresh tokens with reuse detection revoke the grant
      when a rotated token is presented twice.
