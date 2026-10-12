# Architecture

`hyperscale-stack/security` is a transport-agnostic authentication and
authorization toolkit for Go. It is built as a **multi-module Go workspace**:
one core module plus satellite modules for transports, schemes, and stores.
Consumers import only the pieces they need; the core stays free of heavy
transitive dependencies.

## Design goals

- **Transport-agnostic core.** The authentication pipeline knows nothing
  about `net/http`, gRPC, or ConnectRPC. Transports are thin adapters.
- **Small, immutable interfaces.** `Authentication` is read-only; state
  changes produce new values. No mutable `interface{}` credential bag.
- **Composable authorization.** A Voter / `AccessDecisionManager` model
  (Affirmative, Consensus, Unanimous) instead of ad-hoc role checks.
- **Lean dependency graph.** Each module declares the minimum it needs;
  the core is stdlib + `go.opentelemetry.io/otel`.
- **Observability built in.** OpenTelemetry spans are emitted directly by
  each module — there is no separate audit/event abstraction.

## Module map

| Path                        | Import path                            | Purpose                                                                       |
| --------------------------- | -------------------------------------- | ----------------------------------------------------------------------------- |
| `.`                         | `github.com/hyperscale-stack/security` | Core: `Authentication`, `Engine`, `Manager`, `Voter`, `AccessDecisionManager` |
| `./http`                    | `…/security/http`                      | `httpsec` — `net/http` middleware + carrier                                   |
| `./grpc`                    | `…/security/grpc`                      | `grpcsec` — unary/stream interceptors + carrier                               |
| `./connectrpc`              | `…/security/connectrpc`                | `connectrpcsec` — ConnectRPC auth + authorize interceptors                    |
| `./basic`                   | `…/security/basic`                     | HTTP Basic extractor + authenticator                                          |
| `./bearer`                  | `…/security/bearer`                    | Bearer extractor + `TokenVerifier`-based authenticator                        |
| `./password`                | `…/security/password`                  | BCrypt + Argon2id hashers (`NeedsRehash`)                                     |
| `./jwt`                     | `…/security/jwt`                       | `jwtsec` — JWT signer/verifier, JWKS, bearer adapter                          |
| `./session`                 | `…/security/session`                   | Stateless encrypted cookie sessions + CSRF                                    |
| `./oauth2`                  | `…/security/oauth2`                    | OAuth2 server: profiles, grants, client auth, endpoints                       |
| `./oauth2/store/sql`        | `…/security/oauth2/store/sql`          | Production `oauth2.Storage` on `database/sql`                                 |
| `./oauth2/store/redis`      | `…/security/oauth2/store/redis`        | Production `oauth2.Storage` on Redis (Lua atomicity)                          |
| `./oidc/client`             | `…/security/oidc/client`               | `oidcclient` — OpenID Connect Relying Party                                   |
| `./oidc/client/store/sql`   | `…/security/oidc/client/store/sql`     | OIDC `TransactionStore` on `database/sql`                                     |
| `./oidc/client/store/redis` | `…/security/oidc/client/store/redis`   | OIDC `TransactionStore` on Redis (Lua atomicity)                              |
| `./oidc/provider`           | `…/security/oidc/provider`             | `oidcprovider` — OpenID Provider: ID Tokens, UserInfo, Discovery, JWKS        |
| `./saml/sp`                 | `…/security/saml/sp`                   | `samlsp` — SAML 2.0 Service Provider (SP-initiated SSO)                       |
| `./saml/sp/store/sql`       | `…/security/saml/sp/store/sql`         | Production `samlsp.Storage` on `database/sql`                                 |
| `./saml/sp/store/redis`     | `…/security/saml/sp/store/redis`       | Production `samlsp.Storage` on Redis (Lua atomicity)                          |
| `./examples`                | `…/security/examples`                  | Runnable use-case demos                                                       |
| `./internal/integrations`   | (private)                              | Cross-module end-to-end tests                                                 |
| `./internal/interop/oidcop` | (private)                              | OpenID Provider interoperability tests (go-oidc + x/oauth2 as the RP)         |
| `./internal/interop/oidcrp` | (private)                              | OIDC client interoperability tests (zitadel/oidc, headless Chrome)            |
| `./internal/interop/oidcstack` | (private)                           | Our RP against our OP, attacks included; opt-in real PG/MySQL/Redis store runs |
| `./internal/interop/saml`   | (private)                              | SAML interoperability tests (crewjam/saml IdP, Keycloak, shared stores, e2e helper) |

`oauth2/storage/memory` is a sub-package of the `oauth2` module (not a
separate module) — it ships an in-memory `oauth2.Storage` for dev and tests.
`outbound` is a sub-package of the core module (standard library only): the
SSRF-safe `*http.Client` factory used for requests to URLs that come from
configuration or remote metadata — see [Outbound requests](#outbound-requests).
`oidc/client/storage/memory` (an in-memory `TransactionStore`) and
`oidc/client/storetest` (the store conformance suite) are sub-packages of
`oidc/client`; `saml/sp/storage/memory` and `saml/sp/storetest` are,
likewise, packages of the `saml/sp` module.

## Dependency policy

```
core (.)                ← stdlib + go.opentelemetry.io/otel
                           (outbound/ is a stdlib-only sub-package of the core)
http/                   ← core + otel
grpc/                   ← core + otel + google.golang.org/grpc
connectrpc/             ← core + otel + connectrpc.com/connect
basic/                  ← core + password
bearer/                 ← core
password/               ← golang.org/x/crypto
jwt/                    ← core + bearer + oauth2 + go-jose/v4 + otel
session/                ← core + golang.org/x/crypto + otel
oauth2/                 ← core + stdlib
oauth2/store/sql/       ← oauth2 + database/sql
oauth2/store/redis/     ← oauth2 + github.com/redis/go-redis/v9
oidc/client/            ← core + github.com/go-jose/go-jose/v4
oidc/client/store/sql/  ← oidc/client + database/sql
oidc/client/store/redis/ ← oidc/client + github.com/redis/go-redis/v9
oidc/provider/          ← core + oauth2 + jwt (go-jose stays behind jwt)
saml/sp/                ← core + otel + gosaml2 + goxmldsig (≥ v1.6.1)
                          + etree + xml-roundtrip-validator
saml/sp/store/sql/      ← saml/sp + database/sql
saml/sp/store/redis/    ← saml/sp + github.com/redis/go-redis/v9
examples/               ← may depend on every module above
internal/interop/oidcrp/ ← (tests only) oidc/client + zitadel/oidc + chromedp
internal/interop/oidcop/ ← (tests only) oidc/provider + oauth2 + jwt
                           + github.com/coreos/go-oidc/v3 + golang.org/x/oauth2
internal/interop/oidcstack/ ← (tests only) oidc/client + its stores
                           + oidc/provider + oauth2 + jwt
                           + opt-in pgx, go-sql-driver/mysql, go-redis
internal/interop/saml/  ← (tests only) saml/sp + its stores + crewjam/saml + etree
                          + modernc sqlite + pgx + go-sql-driver/mysql
                          + go-redis + miniredis
```

The core MUST NOT depend on gRPC, ConnectRPC, JOSE libraries, OAuth2,
Redis, SQL drivers, HTTP routers, or concrete loggers. This boundary is
what keeps the core importable from any transport. The XML signature stack
of SAML stays inside `saml/sp`, which no other library module imports.

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
  `grpcsec.Carrier` wraps `metadata.MD`; `connectrpcsec.Carrier` wraps
  `http.Header`.
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
- **`connectrpcsec`** — `NewAuthenticationInterceptor` authenticates every
  RPC; `NewAuthorizationInterceptor` enforces an ADM. Both return a
  `connect.Interceptor` covering unary and streaming. `ErrorMapper` turns
  sentinels into `connect.Code`.

## OAuth2

The `oauth2` module is an authorization server, not just a provider:

- **`Profile`** — `Profile20`, `Profile20BCP` (default), `Profile21Draft`.
  The profile gates which grants and PKCE methods are allowed, and is
  enforced at runtime on the grants — PKCE is required, the `plain`
  transformation refused, and refresh-token rotation forced under BCP / 2.1.
  Every client that is not confidential needs PKCE under every profile.
- **Grants** — `authorization_code` (PKCE), `client_credentials`,
  `refresh_token` (rotation + reuse detection), plus the opt-in legacy
  `password` grant (`grant.NewLegacyPassword`, refused outside `Profile20`).
- **Client policy** — fail closed: a client uses only the grant types
  (`Client.GrantTypes`, checked at `/token` for every grant before it runs)
  and requests only the scopes (`Client.Scopes`) it declares, an empty list
  allowing nothing; `client_credentials` is for confidential clients only;
  refresh tokens go to clients declaring `refresh_token`.
- **Client authentication** — `client_secret_basic`, `client_secret_post`,
  `none` (public clients, PKCE required). `/introspect` answers
  confidential clients only.
- **Endpoints** — `/authorize` (RFC 6749 §3.1, `authorization_code` and the
  opt-in legacy `implicit` flow, with an application-supplied consent hook;
  every authorization response names its issuer, RFC 9207),
  `/token`, `/revoke` (RFC 7009), `/introspect` (RFC 7662, with an optional
  `IntrospectionPolicy` deciding which tokens each caller may see),
  `/.well-known/oauth-authorization-server` (RFC 8414). The endpoint path
  prefix used in the metadata document is configurable via
  `ServerConfig.RoutePrefix`.
- **`Storage`** — an interface with explicit atomicity contracts: a
  single-use `ConsumeAuthorizationCode` — consumed codes are retained until
  they expire, so that a replayed code revokes the tokens issued from it —
  and token pairs persisted atomically (`SaveTokenPair`,
  `RotateRefreshToken`) against one authoritative state per token family, so
  that a revoked family (`RevokeRefreshFamily`) can neither be used nor
  issued into — even before its first token, and whatever races the
  revocation. Access and refresh tokens share one backend; codes may live
  elsewhere. Three implementations: in-memory, SQL (Postgres/MySQL/SQLite,
  row locks), Redis (Lua scripts). All three pass the shared
  `oauth2/storetest` conformance suite, which states the guarantees through
  the public API.
- **Issuer binding** — every endpoint resolves the issuer of the request
  through the `IssuerResolver` (the application's realm) before it loads
  the client and before any redirected answer; the code and every token
  record it, and the `authorization_code` and `refresh_token` grants refuse
  them at another issuer. A client implementing `IssuerBoundClient` is
  unknown at the issuers it is not registered at.
- **Extension points** — `ServerConfig.Extension` plugs an optional protocol
  extension, the `oidc/provider` OpenID Provider (below), into the authorization-code
  flow without a second `/token` endpoint and without `oauth2` depending on
  OIDC or JOSE:

  ```
  /authorize  core checks ─► issuer ─► Extension.ValidateAuthorizeRequest ─► ConsentFunc
              ─► Extension.CompleteAuthorization(Consent.ExtensionResult) ─► code {Issuer, ExtensionData}
  /token      grant checks (client, issuer, redirect_uri, PKCE) ─► mint tokens (context copied)
              ─► Extension.ExtendTokenResponse ─► one atomic write ─► {…, id_token}
  ```

  The extension only sees what the core accepted, can only narrow a scope
  and add an `id_token` member, and its grant context (`ExtensionData`)
  travels unchanged through every refresh — the stores refuse a rotation
  that would change it.

Tokens and authorization codes are **never stored in cleartext** — the
store only ever sees a hash.

## OpenID Provider

`oidc/provider` (package `oidcprovider`) is the `oauth2.Extension` of an
OpenID Provider. `oidcprovider.New` builds the `oauth2.Server` with the
provider as its extension and its own `ConsentFunc`; the application plugs
in through three interfaces — `Interaction` (end-user sessions, login and
consent pages), `ClaimsSource` (end-user claims) and `KeySource` (per-issuer
signing and published keys):

```
/authorize  core checks ─► ValidateAuthorizeRequest: OpenID parameters, hint, claims ─► view
            ─► Interaction.Authorize (or AuthorizeSilently for prompt=none) ─► Decision
            ─► CompleteAuthorization: Request.Check, event, offline_access ─► context {auth event, released claims}
/token      grant checks ─► ExtendTokenResponse: context, account (ClaimsSource), ID Token signed (KeySource)
/userinfo   bearer token ─► store lookup: issuer, context, openid ─► ClaimsSource ─► released claims
/.well-known/openid-configuration, /.well-known/jwks.json  ◄─ server configuration + key ring
```

The grant context — the authentication event and the released claims —
travels in the core's `ExtensionData`, unchanged across refreshes: no store
of its own. `Paths` derives every mount path from the issuer and the
server's route prefix; the discovery document advertises exactly those.
See [oidc-provider.md](oidc-provider.md) for the feature matrix.

## OpenID Connect client

The `oidc/client` module is a Relying Party: it logs users in through an
external OpenID Provider and returns a verified identity. It is independent
of the `oauth2` server and of `jwtsec`.

```
StartLogin / Begin                          HandleCallback / Complete
  ├─ binding secret (cookie) ─┐               ├─ response shape + callback URL
  ├─ nonce, PKCE verifier  ◄──┘ HMAC          ├─ Consume(state hash, binding hash)
  ├─ TransactionStore.Save                    ├─ transaction ↔ connection checks, iss
  └─ 303 → authorization endpoint             ├─ code exchange (PKCE, client auth)
                                              └─ ID Token checks → Identity
```

- **One `Client` per connection** — issuer, client registration and a
  redirect URI distinct from every other connection's. `New` runs
  discovery; the metadata issuer must equal the configured one.
- **Browser binding** — `Begin` draws a 256-bit binding secret that the
  user agent keeps (an HttpOnly `__Host-` cookie with the net/http helpers);
  the nonce and the PKCE verifier are HMACs of it, the key of the
  transaction's integrity MAC an HMAC of it under a server-held
  transaction key (`Config.TransactionKeys`), and the store keeps only a
  hash of it and of the state. Reading the store gives nothing that
  completes a login; altering a transaction fails it, whoever runs it.
- **`TransactionStore`** — `Save` never overwrites, `Consume` removes a
  transaction atomically in a pinned decision order (unknown, expired,
  binding mismatch — which keeps it). In-memory, SQL and Redis
  implementations pass `oidc/client/storetest`.
- **ID Token validation** — OpenID Connect Core §3.1.3.7 on top of go-jose:
  asymmetric algorithms only, keys from the issuer's `jwks_uri` through a
  bounded, rate-limited cache, and every claim check including nonce,
  auth_time against `max_age`, acr and at_hash. JSON is decoded strictly
  (no duplicate member names, no two names differing only by case); claims
  are read with exact names (`DecodeClaims`).
- **What stays with the application** — choosing the connection, deploying
  the store, linking an identity (issuer + subject, never email) to an
  account, its own session, and rate limiting login starts. See
  `examples/oidc-client` and [oidc-client.md](oidc-client.md).

The two modules are tested against each other in
`internal/interop/oidcstack` (CI), against independent implementations in
`internal/interop/oidcop` and `internal/interop/oidcrp` (CI), and — opt-in —
through `e2e/oidc` (Tales and Chrome against the two examples) and the
OpenID Foundation conformance suite
(`internal/interop/oidcstack/conformance`); see
[oidc-conformance.md](oidc-conformance.md).

## SAML Service Provider

The `saml/sp` module (package `samlsp`) is the Service Provider side of
SP-initiated Web Browser SSO. It does not plug into the authentication
pipeline: an application calls it from two routes and creates its own
session (for instance with `session`) from the verified identity.

```
BeginLogin ──▶ transaction (store) + __Host- binding cookie ──▶ 302 to the IdP
                                                                     │
CompleteLogin ◀── HTTP-POST SAMLResponse + RelayState + cookie ◀─────┘
    │
    ├─ lexical gate (bounded streaming tokenizer)
    ├─ structural profile on the raw tree (shape, IDs, signature placement,
    │  algorithm allowlist)
    ├─ transaction lookup (browser binding, expiry, connection)
    ├─ gosaml2 / goxmldsig verification (trusted certificates only)
    ├─ processing rules on the verified, decoded values
    └─ atomic consumption, then replay cache ──▶ Identity
```

- **Connections** — the application resolves them (`ConnectionResolver`);
  each has its own SP entity ID, ACS URL and trusted `IdentityProvider`,
  imported once or kept current from the IdP's metadata URL by a
  `MetadataSource`, which fetches through `outbound` (see
  [Outbound requests](#outbound-requests)).
- **Storage** — `TransactionStore` (insert-if-absent, lookup, atomic
  single consumption bound to the browser) and `ReplayCache`
  (insert-if-absent): in-memory, SQL and Redis implementations, checked by
  the shared `saml/sp/storetest` conformance suite.
- **Errors** — every refusal matches `ErrRejected` (which wraps
  `security.ErrInvalidCredentials`) and a typed sentinel; infrastructure
  failures do not.

See [security-considerations.md](security-considerations.md#saml-service-provider)
for the trust policy.

## Outbound requests

Server-side requests to URLs the library does not control — an OpenID
Provider's discovery document and JWK Set, its token and UserInfo
endpoints, a SAML IdP's metadata — go through `outbound.NewClient`. The
URL often comes from a tenant's configuration or from remote metadata, so
the client refuses by default every destination that is not publicly
routable, judged on the address actually dialed (`net.Dialer.ControlContext`,
after DNS resolution), and bounds schemes, hosts, redirects, time and
response sizes. Applications widen the policy explicitly
(`AllowedPrefixes` for an on-premises IdP or the loopback interface in
tests, `AllowHTTP` in development) and narrow it with hooks. See
[security-considerations.md](security-considerations.md#outbound-requests-ssrf).

## Observability

Every long-lived operation opens an OpenTelemetry span. Instrumentation
lives directly in the module that owns the operation; there is no central
audit package. See [observability.md](observability.md) for the full span
catalog. No secret (password, token, code, client secret, raw session ID)
is ever placed on a span attribute — identifiers that need correlation are
hashed first.
