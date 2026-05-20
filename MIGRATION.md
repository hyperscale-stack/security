# Migration & workspace layout

The repository hosts **one** Go workspace (`go.work`) and **several** Go modules.
This layout lets consumers import only the pieces they need, keeps the core
free of heavy transitive dependencies, and lets each module be tagged and
released on its own cadence.

## Modules

| Path                      | Module                                                          | Purpose                                                              | Status (post-Phase 7e) |
| ------------------------- | --------------------------------------------------------------- | -------------------------------------------------------------------- | ---------------------- |
| `.`                       | `github.com/hyperscale-stack/security`                          | Core: transport-agnostic primitives (Authentication, Engine, Voter…) | Done (Phases 2 & 5)    |
| `./http`                  | `github.com/hyperscale-stack/security/http`                     | `httpsec` — `net/http` adapter                                       | Done (Phase 3)         |
| `./grpc`                  | `github.com/hyperscale-stack/security/grpc`                     | `grpcsec` — gRPC unary/stream interceptors                           | Empty (Phase 9)        |
| `./basic`                 | `github.com/hyperscale-stack/security/basic`                    | HTTP Basic extractor + authenticator                                 | Done (Phase 4)         |
| `./bearer`                | `github.com/hyperscale-stack/security/bearer`                   | Bearer extractor + `TokenVerifier`-based authenticator               | Done (Phase 4)         |
| `./password`              | `github.com/hyperscale-stack/security/password`                 | BCrypt + Argon2id hashers                                            | Done (Phase 4)         |
| `./jwt`                   | `github.com/hyperscale-stack/security/jwt`                      | `jwtsec` — JWT signer/verifier + JWKS                                | Done (Phase 6)         |
| `./session`               | `github.com/hyperscale-stack/security/session`                  | Cookie sessions + CSRF                                               | Empty (Phase 10)       |
| `./oauth2`                | `github.com/hyperscale-stack/security/oauth2`                   | OAuth2 server (profiles, grants, endpoints)                          | Done (Phase 7a-7d)     |
| `./oauth2/storage/memory` | `github.com/hyperscale-stack/security/oauth2/storage/memory`    | In-memory `oauth2.Storage` (dev/tests)                               | Done (Phase 7a)        |
| `./oauth2/store/sql`      | `github.com/hyperscale-stack/security/oauth2/store/sql`         | Production storage on `database/sql`                                 | Empty (Phase 8)        |
| `./oauth2/store/redis`    | `github.com/hyperscale-stack/security/oauth2/store/redis`       | Production storage on Redis (Lua atomicity)                          | Empty (Phase 8)        |
| `./examples`              | `github.com/hyperscale-stack/security/examples`                 | Use-case demos (one sub-package per scenario)                        | Empty (Phase 11)       |
| `./example/oauth2`        | `github.com/hyperscale-stack/security/example/oauth2`           | OAuth2 server + Bearer resource-server demo (v2 stack)               | Working                |
| `./internal/integrations` | `github.com/hyperscale-stack/security/internal/integrations`    | Cross-module end-to-end tests (private)                              | Working                |

The legacy v0 packages (`authentication/`, `authentication/credential/`,
`authentication/provider/{dao,oauth2}/`, `authorization/`, and the old
in-tree `password`) were removed in Phase 7e. The core module now depends
only on stdlib + `go.opentelemetry.io/otel` (+ `testify` for its tests).

## Dependency policy (enforced by review until a script lands in Phase 11)

```
core (.)                ← stdlib + go.opentelemetry.io/otel
http/                   ← core + otel
grpc/                   ← core + otel + google.golang.org/grpc
basic/                  ← core + password
bearer/                 ← core
password/               ← golang.org/x/crypto
jwt/                    ← core + bearer + oauth2 + go-jose/v4 + otel
session/                ← core + golang.org/x/crypto
oauth2/                 ← core + otel
oauth2/storage/memory/  ← oauth2
oauth2/store/sql/       ← oauth2 + database/sql
oauth2/store/redis/     ← oauth2 + github.com/redis/go-redis/v9
examples/               ← may depend on every module above
```

The core MUST NOT depend on: gRPC, JWT/JOSE libs, OAuth2, Redis, SQL drivers,
HTTP routers, concrete loggers. As of Phase 7e the core's direct dependency
set is exactly stdlib + `go.opentelemetry.io/otel` (+ `stretchr/testify`
scoped to its own tests) — the legacy `gilcrest/alice`, `rs/zerolog`,
`hyperscale-stack/secure` and `golang.org/x/crypto` dependencies were
dropped when the legacy packages were removed.

## Local development

```sh
make sync         # go work sync
make build        # build all modules
make test         # race + coverage, aggregated into build/coverage.out
make lint         # golangci-lint on every module with the shared config
make tidy         # go mod tidy on every module + go work sync
make generate     # mockery (runs from the core module)
```

The `Makefile` discovers modules dynamically via `find . -name go.mod`, so a
new sub-module is picked up automatically as soon as its `go.mod` lands.

## CI

A single GitHub Actions workflow (`.github/workflows/go.yml`) runs `make sync`,
`make build`, `make test`, and `make lint` against every module in one job,
then publishes the aggregated coverage to Coveralls. `make generate` is
intentionally skipped in CI while the mockery config/tool pin are
reconciled (see LIMITATIONS.md). A more granular matrix (per-module job,
OS spread, testcontainers nightly) will be introduced when Phase 8 needs
real Postgres/Redis runtimes.

## What was moved during Phase 1

- `http/header/` → `internal/header/`
  The package was previously imported by the legacy filters; moving it under
  `internal/` keeps it usable from the core while leaving the `./http`
  module free to host the future `httpsec` adapter on the same import path
  (`github.com/hyperscale-stack/security/http`). The new public path for the
  Authorization-header helper will be re-exposed via `httpsec` in Phase 3.

## What is intentionally **not** in Phase 1

- The new core (`Authentication`, `Carrier`, `Extractor`, `Authenticator`,
  `Manager`, `Engine`, `Voter`, `AccessDecisionManager`) — Phase 2.
- Any code inside `http/`, `grpc/`, `basic/`, `bearer/`, `jwt/`, `session/`,
  `oauth2/`, `oauth2/store/*`, `examples/` beyond a `doc.go` placeholder.
- Extraction of `password/` into its own module — Phase 4.
- A dedicated `otel/` adapter module — **never**: per Axel's decision OTel
  spans live directly inside each module (no `EventSink` abstraction).
- Removal of `gilcrest/alice` from the core — happens when the new HTTP
  middleware (Phase 3) replaces the legacy `FilterHandler`/`Handler`.

## Replace directives

Every sub-module declares `replace github.com/hyperscale-stack/security => ../`
(or `=> ../../` for the SQL/Redis sub-modules) so local development works
without published versions. The CI job runs in this same mode for now; the
script that strips the replaces and tests against pseudo-versions (`v0.0.x`)
will be added in Phase 11 alongside the multi-module release workflow.
