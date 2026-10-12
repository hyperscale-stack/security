# Changelog

All notable changes to this project are documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The library is a multi-module workspace; modules are tagged independently
(`module/vX.Y.Z`). The entries below describe the ground-up rewrite that
replaced the v0 stack.

## [Unreleased]

The whole `v0.x` series is superseded by a transport-agnostic rewrite. The
legacy packages (`authentication/`, `authorization/`, the in-tree
`password` package, `authentication/provider/oauth2`) were removed.

### Added

- **Transport-agnostic core** (`github.com/hyperscale-stack/security`):
  immutable `Authentication`/`Principal`, `Carrier`, `Extractor`,
  `Authenticator`, first-success-wins `Manager`, `Engine`, typed
  `SecurityError` sentinels, and a `Clock` abstraction.
- **Authorization v2**: `Voter`/`Decision`/`Attribute`, an
  `AccessDecisionManager` with Affirmative/Consensus/Unanimous strategies,
  and a `voter/` catalog (`HasRole`, `HasAnyRole`, `HasScope`,
  `HasAuthority`, `HasPermission`, `Authenticated`, `Anonymous`,
  `FullyAuthenticated`, `And`/`Or`/`Not`).
- **HTTP adapter** (`httpsec`): `Middleware`, `Authorize`, a request/response
  `Carrier`, and a configurable `ErrorMapper`.
- **gRPC adapter** (`grpcsec`): unary and stream server interceptors,
  `UnaryAuthorize`/`StreamAuthorize`, a `metadata.MD` carrier, and an
  `ErrorMapper` to `codes.Code`.
- **ConnectRPC adapter** (`connectrpcsec`): `NewAuthenticationInterceptor`
  and `NewAuthorizationInterceptor` returning `connect.Interceptor` values
  (unary + streaming), an `http.Header` carrier, and an `ErrorMapper` to
  `connect.Code`.
- **Schemes**: `basic` (HTTP Basic extractor + authenticator) and `bearer`
  (Bearer extractor + pluggable `TokenVerifier`).
- **Password hashing** (`password`): `Hasher` interface with bcrypt and
  Argon2id implementations, context support, and `NeedsRehash`.
- **JWT** (`jwtsec`): `Signer`/`Verifier`, static and cached-remote JWKS,
  key rotation, `alg=none` and algorithm-confusion defenses, and a
  `bearer.TokenVerifier` adapter.
- **OAuth2 server** (`oauth2`): `Profile` (2.0 / 2.0-BCP / 2.1-draft),
  enforced at runtime on the grants (PKCE required, `plain` PKCE refused,
  refresh-token rotation forced under BCP / 2.1). Grants:
  `authorization_code` (PKCE), `client_credentials`,
  `refresh_token` (rotation + reuse detection), and the opt-in legacy
  `password` grant (`grant.NewLegacyPassword`, refused outside `Profile20`).
  `client_secret_basic`/`_post`/`none` client authentication. Endpoints:
  `/authorize` (authorization_code + opt-in legacy implicit flow, with an
  application-supplied consent hook), `/token`, `/revoke`, `/introspect`,
  and metadata — the metadata endpoint paths are configurable through
  `ServerConfig.RoutePrefix`. A `Storage` interface with explicit atomicity
  contracts.
- **OAuth2 storage backends**: in-memory (`oauth2/storage/memory`), SQL
  (`oauth2/store/sql`, Postgres/MySQL/SQLite), and Redis
  (`oauth2/store/redis`, Lua-script atomicity), all validated by the shared
  `oauth2/storetest` conformance suite.
- **Sessions** (`session`): stateless AES-256-GCM encrypted cookies with key
  rotation, a `Manager` (Login/Get/Touch/Rotate/Logout), and a
  synchronizer-token CSRF helper.
- **OAuth2 error hook**: `ServerConfig.OnError` and `grant.Config.OnError`
  (both `oauth2.ErrorHook`) observe every error the authorization server
  turns into an RFC 6749 §5.2 response — carrying the cause a `server_error`
  never puts on the wire — plus the errors behind an answer that cannot
  carry them, such as the storage failure behind a `/revoke` 503 or a family
  revocation that failed during reuse detection. Purely observational: the
  hook never changes a response.
- **OAuth2 profile consistency checks**: `oauth2.ProfileValidator`, an
  optional `Grant` capability: `oauth2.NewServer` asks every registered
  grant implementing it whether it can honor the active `Profile`, and
  refuses to build the server otherwise; the shipped `refresh_token` grant
  implements it. `grant.ErrRotationRequiresGenerator` reports a
  `refresh_token` grant that has to rotate refresh tokens but has no
  `grant.Config.RefreshTokens` generator to mint the replacement — returned
  by `NewServer`, and the cause of the `server_error` such a grant fails
  with at runtime, before any token is minted or persisted.
- **Observability**: OpenTelemetry spans emitted directly by the core,
  `httpsec`, `grpcsec`, `connectrpcsec`, `jwtsec`, and `session`. See
  [docs/observability.md](docs/observability.md).
- **Documentation**: `docs/architecture.md`, `docs/observability.md`,
  `docs/security-considerations.md`, `docs/migration-from-v0.md`, and a
  refreshed `README.md`.
- **OAuth2 introspection policy**: `ServerConfig.IntrospectionPolicy`
  (`oauth2.IntrospectionPolicy`) decides which active tokens each caller of
  `/introspect` may see — the place to enforce resource and tenant
  boundaries (RFC 7662 §4). It receives the request context, the
  authenticated confidential caller and an `oauth2.IntrospectedToken` (its
  `oauth2.TokenKind`, client, subject, scope, audience, issuance and expiry —
  never the token value). A denial answers a bare `{"active":false}`, the
  same bytes as an unknown token; a policy error fails closed the same way
  and reaches `OnError` as a `server_error`. Optional: without a policy, any
  authenticated confidential client may introspect any token.
- **OAuth2 token-family primitives**: `oauth2.ErrTokenFamilyRevoked`
  (`invalid_grant`) refuses an operation on a revoked token family;
  `oauth2.ErrTokenFamilyRevocationFailed`, a plain sentinel that never
  reaches the wire, reports a family revocation that could not be recorded
  (the family must then be treated as active and the revocation retried);
  `oauth2.TokenPair.Validate` rejects a pair no store may persist (a refresh
  token outside the access token's family, without a family, or already
  consumed); `oauth2.MaxFamilyIDLength` (64 bytes) and
  `oauth2.FamilyRevocationRetention` (24h) bound family identifiers and how
  long a revoked family is remembered.
- **OAuth2 code replay error**: `oauth2.CodeReplayError`, the error an
  `AuthorizationCodeStore` returns for a replayed code it still retains. It
  matches `oauth2.ErrCodeAlreadyUsed` (`invalid_grant`) for `errors.Is`,
  `oauth2.IsCode` and the wire, and carries the retained record for
  `errors.As`.
- **Outbound HTTP guard** (`outbound`, a stdlib-only sub-package of the
  core): `outbound.NewClient(outbound.Policy)` returns the `*http.Client`
  the federation modules use for server-side requests to URLs that come
  from configuration or remote metadata (discovery documents, JWK Sets,
  token and UserInfo endpoints, SAML metadata), against server-side
  request forgery. Its zero-value policy allows https only (http is an
  opt-in, an https→http redirect is always refused), judges the address
  actually connected to — after DNS resolution, so DNS rebinding cannot
  bypass it — and refuses loopback, private (RFC 1918, RFC 4193), shared
  (RFC 6598), link-local and cloud-metadata, multicast, reserved,
  documentation and benchmarking space, IPv4-mapped and NAT64 addresses
  being judged on their IPv4 and IPv6 being limited to `2000::/3` minus
  its special-purpose blocks; it requires ASCII host names and refuses
  those ending in a number (`127.1`, `0x7f.1`, which resolvers read as
  IPv4 addresses) before the `CheckURL` hook, never names a refused
  address in an error, follows no redirect, uses no proxy and no cookie
  jar, bounds the exchange (10 s), the response headers (64 KiB) and every
  body (1 MiB, counted after decompression), and requires TLS 1.2 or
  later. Applications widen it explicitly (`AllowedPrefixes`,
  `AllowHTTP`, `MaxRedirects`) and narrow it with the `CheckURL` and
  `CheckAddr` hooks.
- **OpenID Connect Relying Party** (`oidc/client`, package `oidcclient`):
  logs users in through an OpenID Provider with the Authorization Code flow
  and returns a verified `Identity` (connection, issuer, subject, claims,
  tokens), one `Client` per connection. `New` discovers the provider (the
  metadata issuer must equal the configured one) through the `outbound`
  guard; `Begin`/`Complete` — or the net/http helpers `StartLogin`/
  `HandleCallback` — run the flow with PKCE S256, state and nonce, in the
  `query` or `form_post` response mode, with `client_secret_basic`,
  `client_secret_post` or a public client (`none`, which requires the
  provider to advertise S256). A login is bound to the user agent that
  started it: a 256-bit binding secret kept in an HttpOnly `__Host-` cookie
  (SameSite=Lax for `query`, None for `form_post`), from which the nonce and
  the PKCE verifier are derived, so the transaction store holds no secret,
  and which keys an integrity MAC over every field of the transaction
  (`Transaction.Integrity`, verified before any field is used: a
  transaction altered in the store fails with `ErrTransactionIntegrity`).
  The transaction is also bound to its connection, issuer, client, redirect
  URI and response mode, expires (10 minutes by default), and is consumed
  once. `Complete` requires the URL the response was received on
  (`Callback.URL`) to be the connection's redirect URI — scheme, host,
  port, path and the redirect URI's query parameters; a redirect URI
  distinct per connection is the mix-up defense (RFC 9700 §4.4.2.2) — and
  checks the RFC 9207 `iss` parameter when the provider advertises it;
  `HandleCallback` takes the host from the Host header and the scheme from
  the redirect URI, so that a TLS-terminating proxy preserving Host works. The ID Token is validated per OpenID Connect
  Core §3.1.3.7: an allow-listed asymmetric algorithm (RS*, PS*, ES*,
  EdDSA; HMAC and `none` refused), `typ` absent or JWT, iss, aud (extra
  audiences only if trusted), azp, exp/iat/nbf with a bounded skew, nonce,
  auth_time against `max_age`, acr against the requested `acr_values`, and
  at_hash. Keys come from the issuer's `jwks_uri` only, through a bounded
  cache (1 h TTL, one rate-limited refresh for an unknown `kid`,
  single-flight, 24 h stale limit). Every JSON document is parsed strictly
  (duplicate or case-variant member names refused at every level). Token
  and UserInfo requests never follow redirects. `UserInfo` returns claims
  only when their `sub` equals the identity's. Errors are sentinels
  (`ErrInvalidIDToken` and its causes, `ErrBindingMismatch`,
  `ErrTransactionNotFound`, `ErrIssuerParameter`, …) wrapping
  `security.ErrInvalidCredentials` where a credential is refused;
  `AuthorizationError` and `TokenError` carry the provider's error
  responses. Secrets never appear in errors, `String`/`GoString` or `slog`
  output.
- **OpenID Connect transaction stores**: the `oidcclient.TransactionStore`
  contract (`Save` never overwrites; `Consume` removes a transaction
  atomically and decides unknown, then expired, then binding mismatch,
  which keeps the transaction), with an in-memory store
  (`oidc/client/storage/memory`), a SQL store (`oidc/client/store/sql`,
  PostgreSQL/MySQL/SQLite, `PurgeExpired`) and a Redis store
  (`oidc/client/store/redis`, one Lua script per consumption, Redis Cluster
  compatible), all validated by the exported conformance suite
  `oidc/client/storetest`.
- **OpenID Connect interoperability tests** (`internal/interop/oidcrp`,
  tests only): the Relying Party against the example provider of
  `github.com/zitadel/oidc/v3`, plus an opt-in browser test
  (`OIDC_BROWSER_TESTS=1`, headless Chrome) of the binding cookie's
  SameSite behavior.
- **Example** `examples/oidc-client`: sign-in through several connections
  with distinct callback routes, account linking on (connection, issuer,
  subject), and a local session.

- **OAuth2 protocol extension points** (`oauth2`): `ServerConfig.Extension`
  takes an `oauth2.Extension` — the contract an OpenID Provider (the
  `oidc/provider` module) builds on, without a second `/token` endpoint and
  without `oauth2` depending on OIDC or JOSE. `ValidateAuthorizeRequest`
  validates the extension's own `/authorize` parameters after every core
  check, its view reaching the `ConsentFunc` as
  `AuthorizeRequest.ExtensionRequest`; `CompleteAuthorization` turns the
  application's trusted result (`Consent.ExtensionResult`) into an
  `oauth2.ExtensionGrant` — a scope that can only narrow the grant, and
  opaque `Data` (at most `oauth2.MaxExtensionDataLength`, 4096 bytes of UTF-8
  without NUL) recorded on the code and on every token derived from it, the
  same across refreshes (OIDC Core §12.2, RFC 9068 §2.2.1);
  `ExtendTokenResponse` runs in the `authorization_code` and `refresh_token`
  grants between minting the tokens and their single atomic write, with a
  copy of the access token (OIDC Core §3.1.3.6 `at_hash`), the grant context,
  the code's nonce and whether a refresh token comes with the access token
  (`RefreshTokenIssued`, so an OpenID provider can fail closed on a refresh
  token issued without `offline_access` consent, OIDC Core §11), and returns
  an `oauth2.TokenResponseExtension` whose
  `IDToken` becomes the `id_token` member (`GrantResponse.IDToken`). The RFC
  6749 §5.1 members cannot be overwritten, and no response is partially
  successful: a hook failure persists nothing, and an `id_token` only travels
  with a persisted pair. `GrantRequest.Extension` carries the hook to the
  grants; `oauth2.GrantTypeAuthorizationCode` / `GrantTypeRefreshToken` name
  the exchanges; `oauth2.ErrUnredirectableRequest` lets a hook refuse
  without redirecting; `oauth2.ErrAuthorizeRequestModified` is the cause
  reported when a callback modified the read-only request it was handed.
  See `ExampleExtension`.
- **OAuth2 consent refusals**: `Consent.Refusal` redirects an
  authorization-endpoint error instead of `access_denied` — e.g.
  `oauth2.ErrLoginRequired`, `ErrConsentRequired`, `ErrInteractionRequired`,
  `ErrAccountSelectionRequired`, the new `Code*` constants and `Err*`
  sentinels for the nine OIDC Core §3.1.2.6 codes (`ErrRequestNotSupported`,
  `ErrRequestURINotSupported`, `ErrRegistrationNotSupported`,
  `ErrInvalidRequestURI`, `ErrInvalidRequestObject`).
- **OAuth2 grant context on codes and tokens**: `AuthorizationCode`,
  `AccessToken` and `RefreshToken` gain `Issuer` and `ExtensionData`;
  `AuthorizeRequest.Issuer` and `IntrospectedToken.Issuer` expose the realm
  (an `IntrospectionPolicy` can now enforce it, RFC 7662 §4).
- **OAuth2 refresh-token gate**: `grant.Config.RefreshTokenScope` makes the
  `authorization_code` and legacy `password` grants issue a refresh token
  only when the granted scope holds that scope token — e.g.
  `offline_access` (OIDC Core §11). Opt-in; rotation is unaffected.
- **JWT key publication and signature-only verification** (`jwtsec`):
  `MarshalJWKS` serializes an RFC 7517 JWK Set of public signature keys —
  every key with a unique `kid`, its `alg` and `use: sig` — and refuses
  private or symmetric material, publishing nothing (OIDC Discovery §3);
  `PublicKey.Validate`, `PrivateKey.Validate` and `PrivateKey.Public` bind a
  key to its algorithm (RSA of at least 2048 bits for RS*/PS*, the matching
  curve for ES*, Ed25519 for EdDSA — RFC 7518 §3.3–§3.5, RFC 8725 §3.1);
  `VerifySignature` verifies a compact JWS against a key list (allowlisted
  `alg`, key selected by `kid` and bound to that `alg`) and returns its
  header and payload without validating any claim, for callers applying
  their own claim rules. `ErrInvalidKey` reports an unfit key.
- **JWT explicit typing** (`jwtsec`): `WithType` sets the `typ` header a
  `Signer` writes (`TypeJWT` by default) and makes a `Verifier` require it,
  compared as RFC 7515 §4.1.9 prescribes (case-insensitive, `application/`
  implied) — `ErrInvalidType` otherwise; opt-in on verifiers.
- **OAuth2 issuer identification in authorization responses** (RFC 9207):
  every authorization response — code and implicit, success and redirected
  error — carries `iss`, the issuer the request resolved to, and the RFC 8414
  metadata publishes `authorization_response_iss_parameter_supported: true`,
  so a client talking to several authorization servers or realms can detect
  a mix-up (RFC 9700 §4.4.2.1). The `server_error` answering an
  `IssuerResolver` failure is the one response without it.
- **OAuth2 client ↔ issuer binding**: `oauth2.IssuerBoundClient`
  (`AllowsIssuer`), an optional client capability — implemented by
  `DefaultClient` through `IssuerValues` — for deployments whose
  `IssuerResolver` serves several issuers from one `ClientStore`. At an
  issuer it is not registered at, a client does not exist: `/authorize`
  answers the bare 400 of an unknown client, never redirected, and `/token`,
  `/revoke` and `/introspect` fail its authentication as an unknown
  client's (`401 invalid_client`), whatever the secret — so another realm's
  clients can be neither used nor enumerated. `oauth2.ClientAllowsIssuer`
  applies the rule; `oauth2.ErrClientNotAtIssuer` is the cause `OnError`
  gets. The server now resolves the issuer before it loads the client, at
  every endpoint `/revoke` and `/introspect` included (see
  [MIGRATION.md](MIGRATION.md)).
- **OpenID Provider** (`oidc/provider`, package `oidcprovider`): OpenID
  Connect Core 1.0 (errata set 2) on the `oauth2` extension points — the
  Authorization Code flow with PKCE, signed ID Tokens at the code exchange
  and at every refresh (Core §12.2: the original `auth_time`, `acr` and
  `amr`, no `nonce`), UserInfo (Core §5.3, RFC 6750 errors), Discovery
  (path issuers, only what is served, consistent with RFC 8414) and the
  issuer's public JWK Set. `New` builds the `oauth2.Server` it extends,
  `Paths` tells where to mount each handler. The provider validates
  authentication requests — `prompt`, `max_age`, `nonce`, the `claims`
  parameter, `id_token_hint`; `request`, `request_uri` and `registration`
  refused with their Core §3.1.2.6 codes — and re-checks every approval
  itself: realm, `prompt=login` and `max_age` freshness, designated
  end-user, essential `acr`, `offline_access` consent (Core §11). The
  application keeps the end-user side through typed interfaces:
  `Interaction` (login and consent UI; `prompt=none` gets no
  `ResponseWriter`), `ClaimsSource` (released claims only;
  `ErrUnknownSubject` stops a grant) and `KeySource` (rings validated on
  every use: RS256 required, RSA of at least 2048 bits, private keys never
  published). Access-token audiences equal to a client ID are refused
  (RFC 9068 §5). [docs/oidc-provider.md](docs/oidc-provider.md) is the exact
  feature matrix; no certification is claimed.
- **OpenID Provider interoperability tests** (`internal/interop/oidcop`, private and
  test-only): the provider against `github.com/coreos/go-oidc/v3` and
  `golang.org/x/oauth2` as an independent relying party, over TLS — code
  flow with S256 PKCE, the three client authentication methods, path
  issuers, refresh, key rotation, `prompt=none` and the advertised URLs.
- **Example** `examples/oidc-provider`: a runnable OpenID Provider with its
  own login and consent pages (CSRF tokens, anti-framing headers),
  cookie sessions, `prompt` handling and offline access.

### Changed

- The repository is now a Go workspace (`go.work`) of independent modules,
  so consumers import only the pieces they need and the core stays free of
  heavy transitive dependencies.
- `Authentication` is immutable — authenticators return new values instead
  of mutating their input.
- `context.Context` is the first argument of every runtime operation
  (`Extract`, `Authenticate`, `Hasher.Hash`/`Verify`, `TokenVerifier.Verify`).
- Password `Verify` returns `(bool, error)`, distinguishing a mismatch from
  a malformed hash; v0 returned a bare `bool`.
- The JWT verifier (`jwtsec`) now rejects tokens without an `exp` claim by
  default (`ErrMissingExpiry`), aligning with RFC 9068 §2.2 and the
  fail-closed doctrine. Opt out with `jwtsec.WithOptionalExpiry()` to verify
  deliberately non-expiring assertions.
- **OAuth2 storage contract (breaking).** `oauth2.Storage` drops
  `SaveAccessToken` and `SaveRefreshToken` for `SaveTokenPair`, which
  persists a newly issued pair atomically; `RotateRefreshToken` takes the
  whole replacement `*oauth2.TokenPair` and persists it atomically with the
  consumption of the presented token; `RevokeRefreshFamily` records a family
  revoked even before any of its tokens exists, is idempotent, and rejects
  an empty or over-long ID with `invalid_request`. Every store keeps one
  authoritative state per token family that issuance, rotation and lookups
  go through: a token of a revoked family is no longer usable — its access
  token lookup fails with `invalid_grant`, its refresh token reads consumed
  — and nothing can be issued into it. Access and refresh tokens must share
  one backend. `store/sql` adds the `oauth2_token_families` table (`Migrate`
  creates it); `store/redis` replaces the `famrt:`/`famat:` sets with one
  `fam:{id}` key per family and now requires Redis 6.0 or later
  (`SET … KEEPTTL`) and `maxmemory-policy noeviction`. The guarantees are
  documented on `oauth2.Storage` and checked by `oauth2/storetest`, which
  every implementation must pass. Upgrading invalidates every refresh token
  and every family-bound access token issued before it — their family has no
  record and the stores fail closed — so users re-authenticate, and
  presenting such a refresh token answers `invalid_grant`;
  `client_credentials` and implicit tokens keep working. See
  [MIGRATION.md](MIGRATION.md).
- **OAuth2 authorization-code storage (breaking).**
  `ConsumeAuthorizationCode` no longer deletes the code it consumes: every
  store keeps the record, flagged consumed and without the raw code, at
  least until the code expires, and answers a replay with an
  `*oauth2.CodeReplayError` carrying it; an unknown code still gets
  `ErrCodeAlreadyUsed`. `store/sql` adds a `consumed` column to
  `oauth2_auth_codes` — existing tables need an `ALTER TABLE` — and keeps
  consumed rows until the operator's cleanup; `store/redis` flags the
  code's key and keeps its TTL, and a consumption resent by go-redis after
  a lost reply no longer fails the exchange; the memory store no longer
  keeps the raw code. Every instance must be upgraded at once. See
  [MIGRATION.md](MIGRATION.md).

- **OAuth2 codes and tokens carry an issuer and a grant context
  (breaking).** `AuthorizationCode`, `AccessToken` and `RefreshToken` gain
  `Issuer` and `ExtensionData`, which every store persists byte-exact and
  returns from every read. `TokenPair.Validate` refuses a refresh token whose
  issuer or extension data differ from its access token's, and
  `RotateRefreshToken` refuses, with `invalid_request` and without writing
  anything, a replacement whose issuer or extension data differ from the
  presented token's. `store/sql` adds nullable `issuer` and `extension_data`
  `TEXT` columns to the code and token tables — `Migrate` creates them for new
  installs only, existing databases apply the `ALTER TABLE` statements of
  [MIGRATION.md](MIGRATION.md) (an optional single-issuer backfill keeps users
  signed in); `store/redis` adds optional payload fields. Every instance must
  be upgraded at once.
- **JWT access tokens follow RFC 9068 (breaking)**:
  `jwtsec.NewOAuth2AccessTokenSigner` takes the `PrivateKey` and builds its own
  signer, so every access token is typed `at+jwt` (RFC 9068 §2.1) — a resource
  server verifying with `WithType(TypeAccessToken)` refuses an OpenID Connect
  ID Token signed by the same keys — and carries a random 128-bit `jti`
  (§2.2). It used to wrap any `Signer` and emit `typ: JWT` without `jti`. See
  [MIGRATION.md](MIGRATION.md).
- **OAuth2 `GrantResponse.ExtraParams` removed (breaking)**: it was never
  serialized. `GrantResponse.IDToken` is the typed member a token response
  may add (`id_token`).
- **OAuth2 `/authorize`** resolves the issuer right after the redirect URI is
  trusted, for both flows: a resolver failure answers a redirected
  `server_error` before the `ConsentFunc` runs. The request a `ConsentFunc`
  — or an extension hook — gets is a read-only copy: modifying any field of
  it but `ExtensionRequest`, or the identity of the client it shares, fails
  the authorization with `server_error` (`oauth2.ErrAuthorizeRequestModified`
  at `OnError`) and issues nothing — breaking for a `ConsentFunc` that
  narrowed the grant by rewriting `ar.Scope`, which must use
  `Consent.Scope`; on master the server read the rewritten request back. The
  code is bound to the client ID read at validation. An approval must name
  its subject — non-empty, at most 255 bytes (OIDC Core §2) — or it is
  answered `server_error` and issues nothing (breaking for `ConsentFunc`s
  approving without one). A `ConsentFunc` error still answers `server_error`,
  whatever the error, and its cause now reaches `OnError`.

### Fixed

- The v0 authentication `Handler` no longer iterates past a successful
  authentication and no longer swallows provider errors — the `Manager`
  short-circuits on first success and aggregates failures.
- The OAuth2 client-secret mismatch is now a typed error
  (`ErrClientSecretMismatch`) instead of a silent failure.
- The OAuth2 `/token` response now computes `expires_in` from
  `ServerConfig.Now` instead of the wall clock, so an injected clock stays
  authoritative on the wire; the value is rounded to the nearest second (a
  1h TTL is advertised as `3600`, not `3599`) and an already-expired token
  drops the field rather than sending the negative lifetime RFC 6749 §5.1
  does not allow.
- A rotated OAuth2 refresh token keeps the scope of the token it replaces
  (RFC 6749 §6); narrowing the scope of a refresh only narrows the issued
  access token. The replacement used to inherit the narrowed scope, so the
  grant shrank permanently and a later request for the original scope was
  refused with `invalid_scope`.
- The SQL store's schema (`oauth2/store/sql`) runs on PostgreSQL and MySQL:
  the refresh-token `consumed` flag is a `SMALLINT` — PostgreSQL rejected
  the former `BOOLEAN NOT NULL DEFAULT 0` column and the store's integer
  comparisons — and the token-family indexes are gone, since MySQL rejects
  their `CREATE INDEX IF NOT EXISTS`. `Schema` returns the same DDL for
  every dialect.
- A failed family revocation after a refresh-token reuse the store detects
  is no longer swallowed: the SQL and Redis stores returned the bare
  `ErrRefreshTokenReused` whatever the revocation did. The error now also
  wraps `oauth2.ErrTokenFamilyRevocationFailed` and its cause; the
  `refresh_token` grant then retries the revocation and reports a second
  failure to `grant.Config.OnError`, while the client still gets
  `invalid_grant`. The revocations a reuse triggers now run on a context
  detached from the request, so a client hanging up cannot abort them.
- A failed exchange no longer leaves a live access token behind: the
  `authorization_code`, `refresh_token` and legacy `password` grants
  persisted the access token before minting the refresh token and rotating,
  so a later failure left an access token the client never received. Each
  exchange now persists its tokens in one atomic call.
- A refresh token that disappears between the grant's lookup and its
  rotation — e.g. expired from Redis — is answered `invalid_grant` (RFC 6749
  §5.2) instead of `server_error`.
- `/revoke` no longer answers `200 OK` for a revocation that may not have
  taken effect: when a token lookup fails for another reason than an
  unknown token, the token's family cannot be revoked, or a token outside
  any family cannot be deleted, it answers `503 temporarily_unavailable`
  (RFC 7009 §2.2.1), so the client knows to assume the token still exists
  and retry. An access token is revoked through its family first, and only
  then deleted, so the retry redoes the whole revocation. A failed lookup
  used to skip the revocation silently; every storage failure now reaches
  `ServerConfig.OnError` once, as a `server_error` with its cause. An
  unknown token, or another client's, still answers `200 OK`.
- `RevokeRefreshFamily("")` no longer deletes every access token outside a
  family (`client_credentials`, implicit) in the memory and SQL stores; it
  is rejected with `invalid_request`.
- A rotation whose replacement declares another family than the presented
  token's is refused with `invalid_request`; the Redis store used to revoke
  the declared family, not the stored one, on reuse.
- The `error_description` of `oauth2.ErrRefreshTokenReused` is now
  `refresh token reused`. The former `refresh token reused — family
  revoked` claimed a revocation that may have failed, and its em dash lies
  outside the RFC 6749 §5.2 `error_description` charset.
- `client_secret_basic` (`oauth2/clientauth`) form-decodes the client
  credentials as RFC 6749 §2.3.1 and Appendix B require: the Basic user-id and
  password are split at the first colon, then each is
  `application/x-www-form-urlencoded`-decoded, so a client identifier or
  secret holding reserved or non-ASCII characters — sent encoded, as
  `golang.org/x/oauth2` does — authenticates. Breaking for clients sending
  `%` or `+` unencoded (an unencoded `+` now reads as a space, an invalid
  escape is a malformed header); credentials made of unreserved characters
  are unaffected. The empty-credential guard applies to the decoded values.
  See [MIGRATION.md](MIGRATION.md).

### Removed

- The legacy v0 packages: `authentication/`, `authentication/credential/`,
  `authentication/provider/{dao,oauth2}/`, `authorization/`, and the
  in-tree `password` package.

### Security

- Multi-issuer deployments can keep each client in its realm: with the
  `oauth2.IssuerBoundClient` capability (see Added), a client of one issuer
  can no longer send another issuer's end-users to that issuer's login page
  and obtain their codes, tokens and ID Tokens, nor be told apart from an
  unknown client there. Clients without the capability keep being known at
  every issuer of a shared `ClientStore`.
- Authorization responses name their issuer (RFC 9207, see Added): a client
  of several authorization servers or realms can detect a mix-up attack
  (RFC 9700 §4.4).
- RFC 9068 access tokens are typed `at+jwt` (see Changed), so a verifier
  requiring that type never accepts an OpenID Connect ID Token signed by the
  same keys as an access token (RFC 8725 §3.11).
- The OpenID Provider (see Added) enforces the protocol itself rather than
  trusting the application: `prompt=login`, `max_age` and essential `acr`
  are re-checked on every approval, an authentication counts in its realm
  only, `prompt=none` refusals read the same whatever sessions the browser
  holds, private and symmetric keys are never published, an access-token
  audience equal to a client ID is refused (RFC 9068 §5), and UserInfo only
  serves tokens of clients still registered at the issuer.
- The HTTP `DefaultErrorMapper` no longer reflects the wrapped error chain
  into the `WWW-Authenticate` header. The RFC 6750 `error_description` is now
  a fixed, generic string per error code, so internal context (timestamps,
  package and authenticator names, consumer-supplied `TokenVerifier`/store
  errors) can no longer leak to clients.
- The OAuth2 `refresh_token` grant now enforces the refresh-token rotation
  that `Profile20BCP` (the default) and `Profile21Draft` mandate (RFC 9700
  §4.14.2) — for every client, stricter than RFC 9700 §2.2.2, which only
  requires it (or sender-constrained refresh tokens) for public clients —
  whatever `grant.Config.RotateRefreshTokens` says: every exchange consumes
  the presented refresh token and returns a new one, and replaying a
  consumed token is refused with `invalid_grant` and revokes the whole
  family. The zero configuration used to let the same refresh token be
  replayed until it expired. Clients MUST keep the refresh token returned
  by each exchange (RFC 6749 §6). A grant that has to rotate but has no
  `grant.Config.RefreshTokens` generator — including under `Profile20`
  with `RotateRefreshTokens` set, which used to skip the rotation
  silently — is refused by `oauth2.NewServer`, and should it run anyway
  (called directly, or behind a decorator that hides it from `NewServer`)
  it fails with `server_error` before any token is minted or persisted.
  Non-rotating refresh tokens remain an explicit `Profile20` choice
  (`RotateRefreshTokens: false`).
- OAuth2 token-family revocation is race-free and authoritative in every
  store (RFC 9700 §4.14.2, RFC 7009 §2.1). Once `RevokeRefreshFamily`
  returns — or a reuse is reported without
  `ErrTokenFamilyRevocationFailed` — no token of the family is usable
  through the store, and no issuance or rotation into the family succeeds,
  including one racing the revocation. Before, a rotation or a non-rotating
  `Profile20` refresh could leave a usable token in a family whose
  revocation had just completed: the SQL statements ran outside a shared
  transaction, the Redis revocation enumerated the family non-atomically,
  and nothing gated issuance. A revocation also left no trace for a family
  without tokens yet. A Redis rotation resent by go-redis after a lost
  reply is no longer mistaken for a reuse that revokes the family it just
  rotated into. JWT access tokens verified offline stay out of the store's
  reach until they expire: see
  [docs/security-considerations.md](docs/security-considerations.md).
- The OAuth2 `/introspect` endpoint now answers only clients whose
  `Type()` is `oauth2.ClientConfidential` (RFC 7662 §2.1 / §4, RFC 6749
  §2.2, §2.3). It used to answer any client the shared `ClientAuth` chain
  authenticated, so anyone knowing a public `client_id` — which is not a
  secret — could read the validity and claims of any token they held,
  refresh tokens included: through the `none` method, or through
  `client_secret_basic` / `client_secret_post` with the client's registered
  secret (Basic: even an empty one), whether or not `none` was registered.
  Public clients, whatever the method, and untyped clients (`Type() == ""`)
  authenticated through Basic or Post — `none` already refused them — now
  get `401 invalid_client`. This breaks deployments whose applications, or
  resource servers registered without a type, call `/introspect`. `/token`
  and `/revoke` are unchanged. The `none` method's `error_description` for
  a non-public client no longer contains a double quote, which RFC 6749
  §5.2 forbids. See [MIGRATION.md](MIGRATION.md).
- The OAuth2 server now enforces the RFC 7636 PKCE syntax, not just the
  transformation. `/authorize` answers `invalid_request` to a
  `code_challenge` that is not 43–128 unreserved characters (`plain`) or
  not the unpadded base64url SHA-256 digest (`S256`); for a code bound to a
  `code_challenge`, `/token` answers `invalid_grant` to a `code_verifier`
  that is not 43–128 characters of `A-Z a-z 0-9 - . _ ~`, and the code
  stays consumed — a one-character verifier whose S256 challenge matched
  used to be exchanged for tokens.
  `pkce.Verify`/`VerifyS256` return false for a malformed verifier, and
  `pkce.ValidVerifier`/`pkce.ValidChallenge` expose the checks. Missing or
  unsupported methods and the profile ban on `plain` keep their error
  codes; their `error_description` no longer contains a double quote,
  which RFC 6749 §4.1.2.1 and §5.2 forbid, and no longer echoes an
  unsupported `code_challenge_method`.
- A replayed OAuth2 authorization code now revokes every token issued from
  it — access and refresh tokens, and every later rotation — in every store
  (RFC 6749 §4.1.2, §10.5; RFC 9700 §4.2.4). The `authorization_code` grant
  derives the token family from the code before consuming it, so a replay
  racing the first exchange cannot leave its tokens active: one landing
  before that exchange persists its tokens makes it fail with
  `invalid_grant` — as long as the store keeps the revoked family record
  (see the deployment requirements in
  [docs/security-considerations.md](docs/security-considerations.md)) — and
  one landing after revokes them. Only a replay that would itself have been
  accepted revokes: the code has not expired, and the client it was issued
  to presents it with the same `redirect_uri` and PKCE verifier and may
  still use `authorization_code` (OAuth 2.1 §4.1.3, §7.5.3). A public
  `client_id` is no secret, so unknown codes, other clients and missing or
  wrong verifiers revoke nothing. The replay is still refused with
  `invalid_grant`, and a failed revocation is reported through
  `grant.Config.OnError`. JWT access tokens validated offline stay valid
  until they expire. Previously the tokens issued from a replayed code
  stayed valid.
- OAuth2 `client_secret_basic` no longer authenticates a client with an
  empty password (RFC 6749 §2.3, §10.1). It handed the empty secret of
  `Authorization: Basic base64("<client_id>:")` to the client's
  `SecretMatcher`, and `DefaultClient.SecretMatches` matched it against an
  empty `Secret`: anyone knowing the `client_id` of a client registered
  without a secret authenticated as it at `/token` — obtaining tokens,
  `client_credentials` included — and at `/revoke`, whatever the client's
  type, and at `/introspect` when the client was confidential, reading the
  validity and claims of the tokens they held. `client_secret_basic` now
  answers a missing `client_id` or an empty password with
  `401 invalid_client` (`missing client_id or client_secret`) before
  loading the client, with the guard `client_secret_post`'s `Authenticate`
  already has: no store lookup, one answer for every client.
  `DefaultClient.SecretMatches` never matches an empty `Secret`, and the
  `oauth2.SecretMatcher` contract now says implementations MUST NOT match
  an empty secret: callers of `DefaultClient` are covered, custom matchers
  are told to follow suit. Public clients still authenticate with `none`,
  by design; through it, a public client can still use any grant its
  `GrantTypeValues` allow, `client_credentials` included (RFC 6749 §4.4 is
  not enforced yet; see [MIGRATION.md](MIGRATION.md)). This breaks public
  clients that sent an empty Basic password — they must use `none` — and
  clients registered as confidential or untyped that authenticated with an
  empty Basic password. See [MIGRATION.md](MIGRATION.md).
- OAuth2 authorization codes and refresh tokens are bound to the issuer they
  were issued under (OIDC Core §16.15). In a deployment whose
  `IssuerResolver` serves several realms, a client could redeem a code
  authorized at one issuer, or refresh a token issued there, at another one
  — obtaining tokens, and with an OpenID provider ID Tokens, of realm B for a
  subject of realm A. Both are now refused with `invalid_grant`; a refused
  refresh consumes nothing, and a code replayed at another issuer revokes
  nothing (it could not have redeemed the code). Codes and refresh tokens
  written before the upgrade carry no issuer and are refused — users
  re-authenticate — unless the SQL backfill of [MIGRATION.md](MIGRATION.md)
  applies.
- OAuth2 `/authorize` refuses a `response_mode` it cannot honor — anything
  but the response type's default, `query` for the code flow or `fragment`
  for an enabled implicit flow — with a bare `400` that is never redirected
  (OAuth 2.0 Multiple Response Type Encoding Practices §2.1; OIDC Core 1.0
  incorporating errata set 2, §3.1.2.6), before any other check that would
  redirect. It used to ignore the parameter and answer, code included, in a
  mode the client had not asked for. This breaks clients sending an
  unsupported `response_mode` such as `form_post`. The RFC 8414 metadata now
  publishes `response_modes_supported: ["query"]` — its omission meant
  `["query", "fragment"]` (RFC 8414 §2).
- OAuth2 error responses keep to the RFC 6749 §4.1.2.1 / §5.2 syntax: a
  malformed error code from a grant, an extension or a `Consent.Refusal` is
  answered `server_error` (the original reaching `OnError`), a description or
  `error_uri` outside the charset is left out, and `/authorize` redirects only
  the error codes the authorization endpoint defines. A nil `*oauth2.Error`
  returned by a callback or a grant is answered `server_error` instead of
  panicking (`Error`, `Unwrap` and `IsCode` tolerate a nil receiver). The
  `invalid_scope` and
  `unsupported_response_type` descriptions no longer quote or echo the
  request: the former put a double quote, outside the charset, in every
  `invalid_scope` redirect.
