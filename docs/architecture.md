# Architecture

`hyperscale-stack/security` is a transport-agnostic authentication and
authorization toolkit for Go. It is built as a **multi-module Go workspace**:
one core module plus satellite modules for transports, schemes, and stores.
Consumers import only the pieces they need; the core stays free of heavy
transitive dependencies.

## Design goals

- **Transport-agnostic core.** The authentication pipeline knows nothing
  about `net/http` or gRPC. Transports are thin adapters.
- **Small, immutable interfaces.** `Authentication` is read-only; state
  changes produce new values. No mutable `interface{}` credential bag.
- **Composable authorization.** A Voter / `AccessDecisionManager` model
  (Affirmative, Consensus, Unanimous) instead of ad-hoc role checks.
- **Lean dependency graph.** Each module declares the minimum it needs;
  the core is stdlib + `go.opentelemetry.io/otel`.
- **Observability built in.** OpenTelemetry spans are emitted directly by
  each module — there is no separate audit/event abstraction.

## Module map

| Path                      | Import path                                                  | Purpose                                                              |
| ------------------------- | ------------------------------------------------------------ | -------------------------------------------------------------------- |
| `.`                       | `github.com/hyperscale-stack/security`                       | Core: `Authentication`, `Engine`, `Manager`, `Voter`, `AccessDecisionManager` |
| `./http`                  | `…/security/http`                                            | `httpsec` — `net/http` middleware + carrier                          |
| `./grpc`                  | `…/security/grpc`                                            | `grpcsec` — unary/stream interceptors + carrier                      |
| `./basic`                 | `…/security/basic`                                           | HTTP Basic extractor + authenticator                                 |
| `./bearer`                | `…/security/bearer`                                          | Bearer extractor + `TokenVerifier`-based authenticator               |
| `./password`              | `…/security/password`                                        | BCrypt + Argon2id hashers (`NeedsRehash`)                            |
| `./jwt`                   | `…/security/jwt`                                             | `jwtsec` — JWT signer/verifier, JWKS, bearer adapter                 |
| `./session`               | `…/security/session`                                         | Stateless encrypted cookie sessions + CSRF                           |
| `./oauth2`                | `…/security/oauth2`                                          | OAuth2 server: profiles, grants, client auth, endpoints              |
| `./oauth2/store/sql`      | `…/security/oauth2/store/sql`                                | Production `oauth2.Storage` on `database/sql`                        |
| `./oauth2/store/redis`    | `…/security/oauth2/store/redis`                              | Production `oauth2.Storage` on Redis (Lua atomicity)                 |
| `./examples`              | `…/security/examples`                                        | Runnable use-case demos                                              |
| `./internal/integrations` | (private)                                                    | Cross-module end-to-end tests                                        |

`oauth2/storage/memory` is a sub-package of the `oauth2` module (not a
separate module) — it ships an in-memory `oauth2.Storage` for dev and tests.

## Dependency policy

```
core (.)                ← stdlib + go.opentelemetry.io/otel
http/                   ← core + otel
grpc/                   ← core + otel + google.golang.org/grpc
basic/                  ← core + password
bearer/                 ← core
password/               ← golang.org/x/crypto
jwt/                    ← core + bearer + oauth2 + go-jose/v4 + otel
session/                ← core + golang.org/x/crypto + otel
oauth2/                 ← core + stdlib
oauth2/store/sql/       ← oauth2 + database/sql
oauth2/store/redis/     ← oauth2 + github.com/redis/go-redis/v9
examples/               ← may depend on every module above
```

The core MUST NOT depend on gRPC, JOSE libraries, OAuth2, Redis, SQL
drivers, HTTP routers, or concrete loggers. This boundary is what keeps the
core importable from any transport.

## The authentication pipeline

```
Carrier ──▶ Extractor ──▶ Authentication (pending)
                                │
                                ▼
                         Manager (first-success-wins)
                                │  ┌── Authenticator (basic)
                                ├──┤── Authenticator (bearer)
                                │  └── Authenticator (…)
                                ▼
                       Authentication (authenticated)
                                │
                                ▼
            context.Context enriched via WithAuthentication
```

- **`Carrier`** abstracts a transport message — read credentials, write
  challenges. `httpsec.Carrier` wraps `*http.Request`/`http.ResponseWriter`;
  `grpcsec.Carrier` wraps `metadata.MD`.
- **`Extractor`** pulls raw, unauthenticated credentials from a `Carrier`.
  Returns `(nil, nil)` when its scheme is absent.
- **`Authenticator`** validates a pending `Authentication` and returns an
  authenticated one. `Supports` lets the `Manager` skip out-of-scope inputs.
- **`Manager`** chains authenticators — first success wins, the rest are
  skipped; all-fail produces an aggregated error.
- **`Engine`** is the entry point: it runs the extractors, hands the result
  to the `Manager`, and stores the outcome in the returned context.

## The authorization pipeline

```
Authentication + []Attribute
        │
        ▼
AccessDecisionManager  ──▶  Voter₁ ─┐
  (Affirmative |             Voter₂ ─┼─▶ Grant / Deny / Abstain
   Consensus |               Voter₃ ─┘
   Unanimous)
        │
        ▼
   nil | ErrAccessDenied
```

- **`Attribute`** is an opaque authorization predicate handle: `Role`,
  `Scope`, `Authority`, `Permission`.
- **`Voter`** inspects an `Authentication` against attributes and returns
  `Grant`, `Deny`, or `Abstain`. Voters are pure and concurrency-safe.
- **`AccessDecisionManager`** aggregates voter decisions under a strategy:
  Affirmative (one grant wins), Consensus (majority), Unanimous (one deny
  refuses).

The `voter/` sub-package ships the standard catalog: `HasRole`,
`HasAnyRole`, `HasScope`, `HasAuthority`, `HasPermission`, `Authenticated`,
`Anonymous`, `FullyAuthenticated`, plus `And`/`Or`/`Not` combinators.

## Transport adapters

Adapters are deliberately thin — they translate between a transport message
and a `Carrier`, then map security errors to transport responses.

- **`httpsec`** — `Middleware` runs the `Engine` and enriches the request
  context; `Authorize` runs an `AccessDecisionManager`. `ErrorMapper`
  turns sentinels into HTTP status codes + `WWW-Authenticate`.
- **`grpcsec`** — `UnaryServerInterceptor` / `StreamServerInterceptor`
  authenticate every RPC; `UnaryAuthorize` / `StreamAuthorize` enforce an
  ADM. `ErrorMapper` turns sentinels into `codes.Code`.

## OAuth2

The `oauth2` module is an authorization server, not just a provider:

- **`Profile`** — `Profile20`, `Profile20BCP` (default), `Profile21Draft`.
  The profile gates which grants and PKCE methods are allowed, and is
  enforced at runtime on the grants — PKCE is required and the `plain`
  transformation refused under BCP / 2.1.
- **Grants** — `authorization_code` (PKCE), `client_credentials`,
  `refresh_token` (rotation + reuse detection), plus the opt-in legacy
  `password` grant (`grant.NewLegacyPassword`, refused outside `Profile20`).
- **Client authentication** — `client_secret_basic`, `client_secret_post`,
  `none` (public clients, PKCE required).
- **Endpoints** — `/authorize` (RFC 6749 §3.1, `authorization_code` and the
  opt-in legacy `implicit` flow, with an application-supplied consent hook),
  `/token`, `/revoke` (RFC 7009), `/introspect` (RFC 7662),
  `/.well-known/oauth-authorization-server` (RFC 8414). The endpoint path
  prefix used in the metadata document is configurable via
  `ServerConfig.RoutePrefix`.
- **`Storage`** — an interface with explicit atomicity contracts
  (`ConsumeAuthorizationCode`, `RotateRefreshToken`). Three implementations:
  in-memory, SQL (Postgres/MySQL/SQLite), Redis (Lua scripts). All three
  pass the shared `oauth2/storetest` conformance suite.

Tokens and authorization codes are **never stored in cleartext** — the
store only ever sees a hash.

## Observability

Every long-lived operation opens an OpenTelemetry span. Instrumentation
lives directly in the module that owns the operation; there is no central
audit package. See [observability.md](observability.md) for the full span
catalog. No secret (password, token, code, client secret, raw session ID)
is ever placed on a span attribute — identifiers that need correlation are
hashed first.
