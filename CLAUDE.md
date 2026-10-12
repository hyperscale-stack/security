# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`github.com/hyperscale-stack/security` is a transport-agnostic authentication
and authorization framework for Go — conceptually Spring Security / Symfony
Security for the Go ecosystem. It is a **Go workspace (`go.work`) split into
several independently-releasable modules**, so consumers import only the
pieces they need and the core stays free of heavy transitive dependencies.

The whole `v0.x` series was replaced by a ground-up transport-agnostic
rewrite (the "v2 stack"); the legacy `authentication/` / `authorization/`
packages were removed. The rewrite is functionally complete and currently
`[Unreleased]` — remaining gaps are tracked as GitHub issues, not refactor
phases. Source-of-truth docs:

- `CHANGELOG.md` — what the v2 stack ships.
- `MIGRATION.md` — workspace layout and dependency policy.
- `LIMITATIONS.md` — known gaps and explicitly out-of-scope items.
- `docs/` — `architecture.md`, `oidc-provider.md`, `observability.md`,
  `security-considerations.md`, `migration-from-v0.md`.

## Working rules

These rules are mandatory when working in this repository:

- **Clean code:** write clean, SOLID, testable code. **No overengineering** —
  build for the current requirement, not a hypothetical one.
- **Language:** all code, commit messages, and documentation are in **English**.
  Talk to the user (Axel) in **French**.
- **Tests are mandatory:** always write tests. Target **100% coverage** where
  practical, **never below 80%**.
- **RFC compliance:** anything based on an RFC (OAuth2, JWT, PKCE, ...) MUST
  follow the RFC to the letter.
- **Security:** write secure code with no known vulnerabilities. `gosec` is
  part of the lint gate — keep it clean.
- **Per-step gate:** at the end of every feature/step, **run the tests and the
  linter** (`make test` + `make lint`, or the per-module equivalent). They
  MUST pass.
- **Commit per step:** once tests and lint pass, **commit** the step before
  moving on. Use Conventional Commits with a module scope, as in the git
  history (`feat(oauth2): ...`, `fix(jwt): ...`, `docs(...): ...`).
- **Godoc:** document every public API with godoc. Keep it concise and
  relevant so a developer can pick up the module quickly.

## Commands

All targets operate on **every module in the workspace** (discovered via
`find . -name go.mod`). Run from the repo root:

```sh
make build      # go build ./... in every module
make test       # go test -race -cover in every module, aggregated -> build/coverage.out
make lint       # golangci-lint (shared .golangci.yml) on every module
make tidy       # go mod tidy per module + go work sync
make sync       # go work sync
make bench      # benchmarks across all modules
make coverage   # go tool cover -func on the aggregated profile
make generate   # mockery — currently BROKEN, see "Tooling caveats" below
make e2e        # opt-in browser suites (Tales + Chrome, e2e/saml), never in CI
```

To run a **single test** or work on one module, `cd` into that module first
(each module is its own `go.mod` with `replace` directives back to the core):

```sh
cd oauth2 && go test -race -run TestServer_Token ./...
cd jwt    && go test ./...
```

`make test` aggregates coverage but **excludes example `main()` programs**
(they bind a socket and block); examples are still built, tested, and linted.

CI: `.github/workflows/go.yml` runs `make sync build test lint` against the
whole workspace in one job. `.github/workflows/release.yml` validates the
workspace and cuts a GitHub release on a `module/vX.Y.Z` tag. `make generate`
is intentionally skipped in CI.

## Module layout & dependency policy

| Path                      | Import / pkg name                          | Purpose                                              |
| ------------------------- | ------------------------------------------ | ---------------------------------------------------- |
| `.`                       | `security`                                 | Core transport-agnostic primitives                   |
| `./outbound`              | `.../outbound`                             | SSRF-safe outbound `*http.Client` — **package of the core** |
| `./http`                  | `.../http` → `httpsec`                     | `net/http` adapter (middleware, `Authorize`, carrier) |
| `./grpc`                  | `.../grpc` → `grpcsec`                      | gRPC unary/stream interceptors + `Authorize`         |
| `./connectrpc`            | `.../connectrpc` → `connectrpcsec`          | ConnectRPC auth + authorize interceptors             |
| `./basic`                 | `.../basic`                                | HTTP Basic extractor + authenticator                 |
| `./bearer`                | `.../bearer`                               | Bearer extractor + `TokenVerifier` authenticator     |
| `./password`              | `.../password`                             | BCrypt + Argon2id hashers (`NeedsRehash`)            |
| `./jwt`                   | `.../jwt` → `jwtsec`                        | JWT signer/verifier + JWKS + key rotation            |
| `./session`               | `.../session`                              | Stateless AES-256-GCM cookie sessions + CSRF         |
| `./oauth2`                | `.../oauth2`                               | OAuth2 authorization server                          |
| `./oauth2/storage/memory` | `.../oauth2/storage/memory`                | In-memory `oauth2.Storage` — **package of `oauth2`** |
| `./oauth2/store/sql`      | `.../oauth2/store/sql`                      | Production storage on `database/sql` (PG/MySQL/SQLite) |
| `./oauth2/store/redis`    | `.../oauth2/store/redis`                    | Production storage on Redis (Lua atomicity)          |
| `./oidc/client`           | `.../oidc/client` → `oidcclient`            | OpenID Connect Relying Party (code flow + PKCE)      |
| `./oidc/client/storage/memory` | `.../oidc/client/storage/memory`      | In-memory `TransactionStore` — **package of `oidc/client`** |
| `./oidc/client/storetest` | `.../oidc/client/storetest`                | Store conformance suite — **package of `oidc/client`** |
| `./oidc/client/store/sql` | `.../oidc/client/store/sql` → `sqlstore`    | Transaction store on `database/sql` (PG/MySQL/SQLite) |
| `./oidc/client/store/redis` | `.../oidc/client/store/redis` → `redisstore` | Transaction store on Redis (Lua atomicity)       |
| `./oidc/provider`         | `.../oidc/provider` → `oidcprovider`        | OpenID Provider on the `oauth2` extension points     |
| `./saml/sp`               | `.../saml/sp` → `samlsp`                   | SAML 2.0 Service Provider (SP-initiated SSO)         |
| `./saml/sp/storage/memory` | `.../saml/sp/storage/memory`              | In-memory `samlsp.Storage` — **package of `saml/sp`** |
| `./saml/sp/storetest`     | `.../saml/sp/storetest`                    | Storage conformance suite — **package of `saml/sp`** |
| `./saml/sp/store/sql`     | `.../saml/sp/store/sql` → `sqlstore`       | SAML storage on `database/sql` (PG/MySQL/SQLite)     |
| `./saml/sp/store/redis`   | `.../saml/sp/store/redis` → `redisstore`   | SAML storage on Redis (single-key Lua scripts)       |
| `./examples`              | `.../examples`                             | Runnable demos: basic-http, bearer-jwt, grpc-bearer, connectrpc-bearer, session-web, oauth2, oidc-client, oidc-provider, saml-sp |
| `./internal/integrations` | (private)                                  | Cross-module end-to-end tests                        |
| `./internal/interop/oidcop` | (private, tests only)                    | `oidc/provider` vs go-oidc + x/oauth2 as independent RP |
| `./internal/interop/oidcrp` | (private, tests only)                    | `oidc/client` against zitadel/oidc + opt-in Chrome test |
| `./internal/interop/oidcstack` | (private, tests only)                 | the OIDC stack end to end; opt-in real-backend store runs |
| `./internal/interop/saml` | (private, tests only)                      | `saml/sp` against crewjam's IdP, Keycloak (pinned + opt-in live), shared stores, e2e helper |

`oauth2/storage/memory` is **not** a standalone module — it is a sub-package
of `oauth2`; likewise `oidc/client/storage/memory` and `oidc/client/storetest`
belong to `oidc/client`, and `saml/sp/storage/memory` and `saml/sp/storetest`
to `saml/sp`; `outbound` is a sub-package of the core (stdlib only, the core's
only networking code: every server-side fetch of a configuration- or
metadata-supplied URL MUST go through `outbound.NewClient`). The other rows
are independent modules (own `go.mod`).

**The dependency direction is a hard rule** (enforced by review, see
`MIGRATION.md`): the **core (`.`) must depend only on stdlib +
`go.opentelemetry.io/otel`** (+ `testify` in its own tests). It MUST NOT
import gRPC, ConnectRPC, JOSE/JWT libs, OAuth2, Redis, SQL drivers, HTTP
routers, or concrete loggers. Adapters depend on the core, never the reverse. The
`oauth2` module has **no hard dependency on `jwt`** — JWT access tokens are
wired via an adapter (`jwt` depends on `oauth2`, not the other way).
`oidc/client` depends on the core and go-jose only — neither `oauth2` nor
`jwt`; `coreos/go-oidc` and `golang.org/x/oauth2` are not dependencies (see
the evaluation in `oidc/client/doc.go`). `oidc/provider` depends on core +
`oauth2` + `jwt` only (go-jose stays behind `jwt`; `TestDependencyPolicy`
enforces it); go-oidc and x/oauth2 are allowed only in the test-only
`internal/interop/oidcop` module, as an independent relying party. The
SAML XML-DSig stack (gosaml2, goxmldsig ≥ v1.6.1, etree) stays inside
`saml/sp`; `crewjam/saml`, the SQL drivers (pgx, go-sql-driver/mysql,
modernc sqlite), go-redis and miniredis are test-only dependencies of
`internal/interop/saml`. When adding code, check the allowed-dependency
list in `MIGRATION.md` before adding an import.

Every sub-module declares `replace github.com/hyperscale-stack/security => ../`
(`=> ../../` for `oidc/provider` and `internal/integrations`, `=> ../../../`
for the OAuth2 SQL/Redis stores and the interop modules, `=> ../../../../`
for the OIDC client and SAML SP stores, which also replace
`oidc/client => ../../` or `saml/sp => ../../`) plus
one per in-repo module of its graph, so local dev works without published
versions. New modules declare `go 1.26.5`, like the core.

## Core architecture

A request flows through this pipeline (all of it transport-agnostic — HTTP
and gRPC are just adapters):

```
Carrier ──> Extractor ──> Authentication ──> Manager/Authenticator ──> Engine
                                                                         │
                                          AccessDecisionManager/Voter <──┘
```

- **`Carrier`** — abstracts a transport message (HTTP request, gRPC metadata)
  with `http.Header`-like Get/Set/Add/Values. Adapters wrap it.
- **`Extractor`** — pulls raw credentials from a `Carrier` into an
  *unauthenticated* `Authentication`. Returns `(nil, nil)` when its scheme is
  absent (engine tries the next); `(nil, err)` when present-but-malformed.
- **`Authentication`** — **immutable snapshot** of a security context
  (Principal, Credentials, Authorities, IsAuthenticated, Name). Every state
  change produces a *new value*; implementations MUST NOT be mutated. Safe
  for concurrent reads with no synchronization.
- **`Authenticator`** — two-step: `Supports()` (cheap type switch, no I/O)
  then `Authenticate()` returns a *new* authenticated value or a wrapped
  sentinel error.
- **`Manager`** — chains authenticators, **first-success-wins** in
  registration order; joins errors; returns `ErrUnsupportedCredential` when
  none support the credential.
- **`Engine`** — top-level entry point: runs extractors, hands the result to
  the Manager, returns a context enriched via `WithAuthentication`.
- **Authorization** — `Voter` returns `Decision` (Grant/Deny/Abstain) over a
  set of `Attribute`s; `AccessDecisionManager` combines votes with an
  `affirmative` / `consensus` / `unanimous` strategy (mirrors Spring
  Security). Stock voters live in `voter/` (`HasRole`, `HasAnyRole`,
  `HasScope`, `HasAuthority`, `HasPermission`, `Authenticated`, `Anonymous`,
  `FullyAuthenticated`); compose them with `And`/`Or`/`Not`.

Conventions baked into the core:
- **Fail closed by default.** No credentials → `Anonymous()`; voters deny
  unless one explicitly grants. The HTTP middleware rejects with 401 unless
  `WithAnonymousFallback` is set.
- **Errors are sentinels** (`errors.go`) implementing the unexported
  `SecurityError` marker. Always wrap with `fmt.Errorf("...: %w", ErrXxx)`;
  callers match with `errors.Is`/`errors.As`, never string matching.
- **Context first.** `context.Context` is the first argument of every
  runtime operation (`Extract`, `Authenticate`, `Hasher.Hash`/`Verify`,
  `TokenVerifier.Verify`). It also carries the `Authentication` under an
  unexported key — `WithAuthentication` / `FromContext` (returns
  `Anonymous()` when absent).
- **OTel spans live directly in each module** — there is intentionally no
  `EventSink` abstraction and no separate `otel/` module. The core uses
  scope `github.com/hyperscale-stack/security`; each instrumented module
  (`httpsec`, `grpcsec`, `connectrpcsec`, `jwtsec`, `session`, `samlsp`) uses its own. See
  `docs/observability.md` for the span catalog.

## OAuth2 server (`oauth2/`)

`oauth2.NewServer(ServerConfig{...})` aggregates `Profile`, `Storage`,
`ClientStore`, `IssuerResolver`, `Grants`, and `ClientAuth`, and exposes one
`http.Handler` per RFC endpoint: `AuthorizeHandler`, `TokenHandler`,
`RevokeHandler`, `IntrospectHandler`, `MetadataHandler` (endpoint paths
configurable via `ServerConfig.RoutePrefix`).

- `Profile` (2.0 / 2.0-BCP / 2.1-draft) is enforced at runtime on the grants
  — PKCE required and `plain` PKCE refused under BCP/2.1; legacy `password`
  and `implicit` flows refused outside `Profile20`.
- Sub-packages: `grant/` (`authorization_code`, `client_credentials`,
  `refresh_token` with rotation + reuse detection, opt-in legacy `password`),
  `clientauth/` (`client_secret_basic` / `_post` / `none`), `token/` (opaque +
  JWT generators), `pkce/`.
- Access/refresh tokens and authz codes are stored **hashed** (`HashToken`).
- Every authorization is **bound to its issuer**: every endpoint resolves it
  first (the `IssuerResolver` is the realm), codes and tokens record it, and
  the `authorization_code` / `refresh_token` grants refuse it elsewhere. A
  client implementing `IssuerBoundClient` (`DefaultClient.IssuerValues`) is
  unknown at other issuers — same bytes as an unknown `client_id`.
- **Extension points** (`ServerConfig.Extension`, `oauth2.Extension`): the
  contract `oidc/provider` builds on — `ValidateAuthorizeRequest` after the
  core checks, `CompleteAuthorization` turning `Consent.ExtensionResult` into
  an `ExtensionGrant` (narrowing scope + opaque `ExtensionData` ≤ 4 KiB,
  copied onto every token, unchanged across refreshes), `ExtendTokenResponse`
  between minting and the single atomic write (typed `id_token`). Protocol
  refusals go through `Consent.Refusal` (`oauth2.ErrLoginRequired`, …);
  `grant.Config.RefreshTokenScope` gates refresh tokens on a scope
  (`offline_access`). `oauth2` never imports OIDC/JOSE.
- `Storage` implementations: `oauth2/storage/memory` (dev/tests),
  `oauth2/store/sql`, `oauth2/store/redis`. Every implementation must pass
  the shared `oauth2/storetest` conformance suite; `store/sql`'s `Migrate`
  only creates tables — schema additions ship as `ALTER` statements in
  `MIGRATION.md`.

## OpenID Provider (`oidc/provider/`)

`oidcprovider.New(oauth2.ServerConfig{...}, oidcprovider.Config{Keys, Claims,
Interaction})` builds the `oauth2.Server` with the provider as its
`Extension` and owns its `ConsentFunc`; `Provider.Paths(issuer)` gives the
mount path of every handler (`AuthorizeHandler`, `UserInfoHandler`,
`DiscoveryHandler`, `JWKSHandler`, plus the server's own).

- The application implements `Interaction` (login/consent UI; `prompt=none`
  goes to `AuthorizeSilently`, without a `ResponseWriter`), `ClaimsSource`
  (`ErrUnknownSubject` stops a grant) and `KeySource` (per-issuer
  `KeyRing`, validated on every use, RS256 required).
- The provider enforces the protocol itself: request validation (OIDC Core
  §3.1.2), `Request.Check` on every approval (realm, `prompt=login`,
  `max_age`, designated subject, essential `acr`), `offline_access` consent
  (Core §11), ID Tokens at code exchange and refresh (Core §12.2),
  UserInfo with RFC 6750 errors.
- The grant context (authentication event + released claims) travels in the
  core's `ExtensionData` — no storage of its own.
- `docs/oidc-provider.md` is the exact feature matrix (no certification
  claimed); `internal/interop/oidcop` checks interop with go-oidc.

`examples/oauth2/main.go` is the canonical wiring example for the v2 stack;
`examples/oidc-provider` the one for the OpenID Provider (login and consent
pages, CSRF, sessions); `examples/` also has `basic-http`, `bearer-jwt`,
`grpc-bearer`, `connectrpc-bearer`, `session-web`, `oidc-client` and `saml-sp` demos.

## OpenID Connect client (`oidc/client/`)

`oidcclient.New(ctx, Config{...})` builds the Relying Party of **one
connection** (issuer + client registration + redirect URI) after discovery;
`Begin`/`Complete` run the Authorization Code flow with PKCE S256, state and
nonce, and `StartLogin`/`HandleCallback` wrap them for `net/http` (binding
cookie included). `UserInfo` fetches claims whose `sub` must match.

- **Invariants**: the issuer comes from configuration only; every fetch goes
  through `outbound`; token and UserInfo requests follow no redirect; a
  login is bound to the user agent by a binding secret from which the nonce
  and PKCE verifier are derived (the store holds no secret) and which, with
  a REQUIRED server-held key (`Config.TransactionKeys`: the first MACs, all
  verify), keys the transaction's integrity MAC (`integrityFor`, verified
  in `Complete` before any stored field is used; every store persists
  `Integrity`); a
  transaction is consumed once, in the pinned order of
  `TransactionStore.Consume`;
  `Callback.URL` must be the connection's redirect URI — scheme, host,
  port, path and its query parameters (mix-up defense — redirect URIs are
  distinct per connection; `HandleCallback` takes the host from `r.Host`
  and the scheme from the redirect URI); nothing is returned
  before the ID Token is fully validated; every JSON document goes through
  the strict decoder (`strictjson.go`); errors, `String`, `GoString` and
  `LogValue` never carry secrets.
- Every `TransactionStore` (`storage/memory`, `store/sql`, `store/redis`)
  must pass `oidc/client/storetest.RunConformance`.
- Tests use the scriptable fake provider of `fakeop_test.go`;
  `internal/interop/oidcrp` runs the client against zitadel/oidc and a
  pinned corpus of real providers' discovery documents
  (`testdata/metadata`); its Chrome test runs with `OIDC_BROWSER_TESTS=1`,
  its live discovery check with `OIDC_LIVE_DISCOVERY=1` (Internet, no
  credentials).

## SAML Service Provider (`saml/sp/`)

`samlsp.New(Config{...})` takes a `ConnectionResolver` (each `Connection` has
its own SP entity ID, ACS URL and trusted `IdentityProvider`), a
`TransactionStore` and a `ReplayCache`. `BeginLogin` (HTTP-Redirect
AuthnRequest + `__Host-samlsp` browser-binding cookie) and `CompleteLogin`
(HTTP-POST ACS) are the flow; `Metadata`/`ServeMetadata` publish SP
metadata; `ParseIdentityProviderMetadata` imports trusted IdP metadata, and
`FetchIdentityProviderMetadata`/`MetadataSource` fetch it from a configured
URL through `outbound` (pinned entity ID, bounded refresh, never triggered
by response content).

- Validation is layered: streaming lexical gate (`xmlgate.go`) → structural
  profile on the raw etree (`precheck*.go`) → gosaml2/goxmldsig verification
  (`verify.go`) → processing rules on the verified decoded values
  (`postcheck.go`) → atomic consumption → replay mark. Never read identity
  data from the raw tree; never write XML-DSig/C14N code.
- Strict by default: SHA-1 only via `Connection.InsecureAllowSHA1`;
  ambiguous shapes and encrypted assertions refused with typed errors.
  Every refusal matches `ErrRejected` (wraps
  `security.ErrInvalidCredentials`); store/resolver failures do not.
- `Storage` implementations: `saml/sp/storage/memory` (dev/tests),
  `saml/sp/store/sql`, `saml/sp/store/redis`; all must pass
  `saml/sp/storetest`.
- `saml/sp/testdata/corpus` pins 359 signed adversarial responses, stored
  uncompressed (review them as text diffs); after a
  deliberate change regenerate it with `go test -run '^TestCorpusGenerate$'
  -count=1 . -args -corpus.update` (in `saml/sp`): regeneration is
  byte-identical, and `TestCorpusCoversEveryRule` requires every refusal
  rule of the sources in some entry (or in its documented allowlist).
- `internal/interop/saml` runs the SP against crewjam's IdP, replays the
  pinned Keycloak responses (`testdata/keycloak-*`), races instances on
  shared stores and tests metadata retrieval. Opt-in, with
  `internal/interop/saml/compose.yaml`: `SAMLSP_KEYCLOAK_URL` +
  `SAMLSP_KEYCLOAK_ADMIN_PASSWORD` (`TestKeycloakLive`; `-args
  -keycloak.capture` rewrites the 26.7.4 captures, and only `-args
  -keycloak.fixture` against Keycloak 26.0.7 rewrites the 26.0.7 fixture),
  `SAMLSP_REDIS_ADDR`, `SAMLSP_POSTGRES_DSN`, `SAMLSP_MYSQL_DSN`.
- `e2e/saml/*.tales` (`make e2e`, `e2e/saml/run.sh`) drives
  `examples/saml-sp` in Chrome; its sites are served by
  `TestE2EHelperProcess` (skipped unless `SAMLSP_E2E_SERVE` is set). CI
  never runs it: re-run `make e2e` after any change to the example or to
  `samlsp`'s cookie, login or ACS code. The
  integration guide is `docs/saml-sp.md`.

## Tooling caveats

- **`make generate` is broken**: `.mockery.yaml` uses mockery v3 syntax but
  `go.mod` pins the v2 tool (`vektra/mockery v2.53.5`). No module depends on
  generated mocks — **all tests use hand-written fakes**. Don't rely on
  `make generate`; write a fake.
- **Lint**: `golangci-lint v2`, `default: none` + ~30 explicitly-enabled
  linters including `gosec`, `wrapcheck`, `errorlint`, `wsl_v5`,
  `forcetypeassert`. `gocyclo` max complexity 18. Tests are excluded from
  lint (`run.tests: false`). All wrapped errors must keep `%w`.
- Go 1.26. Indentation: tabs in `.go` and `Makefile`, 4 spaces elsewhere,
  2 spaces in YAML (see `.editorconfig`). All source files carry the MIT
  copyright header.
