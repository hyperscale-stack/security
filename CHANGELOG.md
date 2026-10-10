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
  token lookup fails with `invalid_grant`, its refresh token reads consumed —
  and nothing can be issued into it. Access and refresh tokens must share
  one backend. `store/sql` adds the `oauth2_token_families` table
  (`Migrate` creates it); `store/redis` replaces the `famrt:`/`famat:` sets
  with one `fam:{id}` key per family. The guarantees are documented on
  `oauth2.Storage` and checked by `oauth2/storetest`, which every
  implementation must pass. Upgrading invalidates every refresh token and
  every family-bound access token issued before it — their family has no
  record and the stores fail closed — so users re-authenticate, and
  presenting such a refresh token answers `invalid_grant`;
  `client_credentials` and implicit tokens keep working. See
  [MIGRATION.md](MIGRATION.md).

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

### Removed

- The legacy v0 packages: `authentication/`, `authentication/credential/`,
  `authentication/provider/{dao,oauth2}/`, `authorization/`, and the
  in-tree `password` package.

### Security

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
