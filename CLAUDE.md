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
- `docs/` — `architecture.md`, `observability.md`,
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
| `./examples`              | `.../examples`                             | Runnable demos: basic-http, bearer-jwt, grpc-bearer, connectrpc-bearer, session-web, oauth2 |
| `./internal/integrations` | (private)                                  | Cross-module end-to-end tests                        |

`oauth2/storage/memory` is **not** a standalone module — it is a sub-package
of `oauth2`. The other rows are independent modules (own `go.mod`).

**The dependency direction is a hard rule** (enforced by review, see
`MIGRATION.md`): the **core (`.`) must depend only on stdlib +
`go.opentelemetry.io/otel`** (+ `testify` in its own tests). It MUST NOT
import gRPC, ConnectRPC, JOSE/JWT libs, OAuth2, Redis, SQL drivers, HTTP
routers, or concrete loggers. Adapters depend on the core, never the reverse. The
`oauth2` module has **no hard dependency on `jwt`** — JWT access tokens are
wired via an adapter (`jwt` depends on `oauth2`, not the other way). When
adding code, check the allowed-dependency list in `MIGRATION.md` before
adding an import.

Every sub-module declares `replace github.com/hyperscale-stack/security => ../`
(`=> ../../../` for the SQL/Redis stores) so local dev works without
published versions.

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
  (`httpsec`, `grpcsec`, `connectrpcsec`, `jwtsec`, `session`) uses its own. See
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
- `Storage` implementations: `oauth2/storage/memory` (dev/tests),
  `oauth2/store/sql`, `oauth2/store/redis`. Every implementation must pass
  the shared `oauth2/storetest` conformance suite.

`examples/oauth2/main.go` is the canonical wiring example for the v2 stack;
`examples/` also has `basic-http`, `bearer-jwt`, `grpc-bearer`,
`connectrpc-bearer`, and `session-web` demos.

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
