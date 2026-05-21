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
  enforced at runtime on the grants (PKCE required, `plain` PKCE refused
  under BCP / 2.1). Grants: `authorization_code` (PKCE), `client_credentials`,
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
- **Observability**: OpenTelemetry spans emitted directly by the core,
  `httpsec`, `grpcsec`, `connectrpcsec`, `jwtsec`, and `session`. See
  [docs/observability.md](docs/observability.md).
- **Documentation**: `docs/architecture.md`, `docs/observability.md`,
  `docs/security-considerations.md`, `docs/migration-from-v0.md`, and a
  refreshed `README.md`.

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

### Fixed

- The v0 authentication `Handler` no longer iterates past a successful
  authentication and no longer swallows provider errors — the `Manager`
  short-circuits on first success and aggregates failures.
- The OAuth2 client-secret mismatch is now a typed error
  (`ErrClientSecretMismatch`) instead of a silent failure.

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
