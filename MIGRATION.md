# Migration & workspace layout

The repository hosts **one** Go workspace (`go.work`) and **several** Go modules.
This layout lets consumers import only the pieces they need, keeps the core
free of heavy transitive dependencies, and lets each module be tagged and
released on its own cadence.

## Modules

| Path                        | Module                                                         | Purpose                                                                              |
| --------------------------- | -------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| `.`                         | `github.com/hyperscale-stack/security`                         | Core: transport-agnostic primitives (Authentication, Engine, Voter…)                 |
| `./http`                    | `github.com/hyperscale-stack/security/http`                    | `httpsec` — `net/http` adapter                                                       |
| `./grpc`                    | `github.com/hyperscale-stack/security/grpc`                    | `grpcsec` — gRPC unary/stream interceptors                                           |
| `./connectrpc`              | `github.com/hyperscale-stack/security/connectrpc`              | `connectrpcsec` — ConnectRPC auth + authorize interceptors                           |
| `./basic`                   | `github.com/hyperscale-stack/security/basic`                   | HTTP Basic extractor + authenticator                                                 |
| `./bearer`                  | `github.com/hyperscale-stack/security/bearer`                  | Bearer extractor + `TokenVerifier`-based authenticator                               |
| `./password`                | `github.com/hyperscale-stack/security/password`                | BCrypt + Argon2id hashers                                                            |
| `./jwt`                     | `github.com/hyperscale-stack/security/jwt`                     | `jwtsec` — JWT signer/verifier + JWKS                                                |
| `./session`                 | `github.com/hyperscale-stack/security/session`                 | Stateless encrypted cookie sessions + CSRF                                           |
| `./oauth2`                  | `github.com/hyperscale-stack/security/oauth2`                  | OAuth2 server (profiles, grants, endpoints)                                          |
| `./oauth2/store/sql`        | `github.com/hyperscale-stack/security/oauth2/store/sql`        | Production storage on `database/sql`                                                 |
| `./oauth2/store/redis`      | `github.com/hyperscale-stack/security/oauth2/store/redis`      | Production storage on Redis (Lua atomicity)                                          |
| `./oidc/client`             | `github.com/hyperscale-stack/security/oidc/client`             | `oidcclient` — OpenID Connect Relying Party (Authorization Code + PKCE)              |
| `./oidc/client/store/sql`   | `github.com/hyperscale-stack/security/oidc/client/store/sql`   | OIDC transaction store on `database/sql`                                             |
| `./oidc/client/store/redis` | `github.com/hyperscale-stack/security/oidc/client/store/redis` | OIDC transaction store on Redis (Lua atomicity)                                      |
| `./oidc/provider`           | `github.com/hyperscale-stack/security/oidc/provider`           | `oidcprovider` — OpenID Provider on the `oauth2` extension points                    |
| `./saml/sp`                 | `github.com/hyperscale-stack/security/saml/sp`                 | `samlsp` — SAML 2.0 Service Provider (SP-initiated Web SSO)                          |
| `./saml/sp/store/sql`       | `github.com/hyperscale-stack/security/saml/sp/store/sql`       | SAML transactions + replay cache on `database/sql`                                   |
| `./saml/sp/store/redis`     | `github.com/hyperscale-stack/security/saml/sp/store/redis`     | SAML transactions + replay cache on Redis (Lua atomicity)                            |
| `./examples`                | `github.com/hyperscale-stack/security/examples`                | Runnable use-case demos (one sub-package per scenario)                               |
| `./internal/integrations`   | `github.com/hyperscale-stack/security/internal/integrations`   | Cross-module end-to-end tests (private)                                              |
| `./internal/interop/oidcop` | `github.com/hyperscale-stack/security/internal/interop/oidcop` | OpenID Provider interoperability tests with go-oidc + x/oauth2 (private, tests only) |
| `./internal/interop/oidcrp` | `github.com/hyperscale-stack/security/internal/interop/oidcrp` | OIDC client interoperability tests against zitadel/oidc (private, tests only)        |
| `./internal/interop/oidcstack` | `github.com/hyperscale-stack/security/internal/interop/oidcstack` | Our RP against our OP end to end, attacks included; opt-in real-backend runs of the client stores (private, tests only) |
| `./internal/interop/saml`   | `github.com/hyperscale-stack/security/internal/interop/saml`   | SAML interoperability tests: crewjam/saml IdP, Keycloak, shared stores, e2e helper (private, tests only) |

`oauth2/storage/memory` is a sub-package of the `oauth2` module (not a
standalone module): it ships the in-memory `oauth2.Storage` used for dev
and tests. Likewise `outbound` is a sub-package of the core module: the
SSRF-safe `*http.Client` factory the federation modules use to fetch
configuration-supplied URLs. It depends on the standard library only and
is the only networking code of the core. `oidc/client/storage/memory`
(in-memory transaction store) and `oidc/client/storetest` (the conformance
suite every transaction store passes) are sub-packages of the
`oidc/client` module, as `saml/sp/storage/memory` (the in-memory
`samlsp.Storage`) and `saml/sp/storetest` (its conformance suite) are of
the `saml/sp` module.

The legacy v0 packages (`authentication/`, `authentication/credential/`,
`authentication/provider/{dao,oauth2}/`, `authorization/`, and the old
in-tree `password`) were removed during the rewrite. The core module's
non-test imports are now stdlib + `go.opentelemetry.io/otel`; its tests also
use `testify` and `otel/sdk`.

`tools/golangci-lint`, `tools/govulncheck` and `tools/mockery` are not
library modules: each pins one development tool, outside `go.work`, so the
tools' dependencies never reach a library `go.mod` or a consumer's module
graph. They are never released.

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
jwt/                    ← core (outbound included) + bearer + oauth2 + go-jose/v4 + otel
session/                ← core + golang.org/x/crypto + otel
oauth2/                 ← core + stdlib
oauth2/store/sql/       ← oauth2 + database/sql
oauth2/store/redis/     ← oauth2 + github.com/redis/go-redis/v9
oidc/client/            ← core + github.com/go-jose/go-jose/v4
oidc/client/store/sql/  ← oidc/client + database/sql
oidc/client/store/redis/ ← oidc/client + github.com/redis/go-redis/v9
oidc/provider/          ← core + oauth2 + jwt (go-jose stays behind jwt)
saml/sp/                ← core + otel + github.com/russellhaering/gosaml2
                          + github.com/russellhaering/goxmldsig (≥ v1.6.1)
                          + github.com/beevik/etree
                          + github.com/mattermost/xml-roundtrip-validator
saml/sp/store/sql/      ← saml/sp + database/sql
saml/sp/store/redis/    ← saml/sp + github.com/redis/go-redis/v9
examples/               ← may depend on every module above
internal/interop/oidcrp/ ← (tests only) oidc/client + github.com/zitadel/oidc/v3
                           + github.com/chromedp/chromedp
internal/interop/oidcop/ ← (tests only) oidc/provider + oauth2 + jwt
                           + github.com/coreos/go-oidc/v3 + golang.org/x/oauth2
internal/interop/oidcstack/ ← (tests only) oidc/client + its stores
                           + oidc/provider + oauth2 + jwt
                           + opt-in drivers github.com/jackc/pgx/v5,
                           github.com/go-sql-driver/mysql, go-redis;
                           imports no third-party OpenID Connect, OAuth 2.0
                           or JOSE library (go-jose comes with oidc/client,
                           under test)
internal/interop/saml/  ← (tests only) saml/sp + saml/sp/store/{sql,redis}
                           + github.com/crewjam/saml + github.com/beevik/etree
                           + modernc.org/sqlite + github.com/jackc/pgx/v5
                           + github.com/go-sql-driver/mysql
                           + github.com/redis/go-redis/v9
                           + github.com/alicebob/miniredis/v2

(`oauth2/storage/memory` is a sub-package of the `oauth2` module;
`oidc/client/storage/memory` and `oidc/client/storetest` are sub-packages
of the `oidc/client` module; `saml/sp/storage/memory` and
`saml/sp/storetest` of the `saml/sp` module.)
```

`oidc/client` depends on neither `oauth2` nor `jwt`: the Relying Party
validates ID Tokens itself on top of go-jose. `github.com/coreos/go-oidc`
and `golang.org/x/oauth2` are not dependencies of any production module
(see the package documentation of `oidc/client` for the evaluation).

The core MUST NOT depend on: gRPC, ConnectRPC, JWT/JOSE libs, OAuth2, Redis,
SQL drivers, HTTP routers, or concrete loggers. Its non-test imports are
exactly stdlib + `go.opentelemetry.io/otel`; its tests also use
`stretchr/testify` (with `stretchr/objx` behind the generated testify mocks)
and `otel/sdk`. No development tool is a dependency of any library module:
the tools live in their own modules under `tools/`. The policy is enforced by
review. `oauth2` never imports OIDC or JOSE:
`oidc/provider` plugs into its extension points, and imports no relying-party
library, store driver or template engine (`TestDependencyPolicy`). go-oidc
and x/oauth2 are confined to the test-only `internal/interop/oidcop` module,
as an independent relying party.

The SAML XML signature stack (gosaml2, goxmldsig, etree) is confined to
`saml/sp`: no other library module imports it, and nothing imports
`saml/sp` but its stores, the examples and the private interop tests.
`github.com/crewjam/saml` is a test-only dependency of the private
`internal/interop/saml` module; it never reaches a library build, and
neither do that module's SQL drivers, Redis clients and miniredis. The
opt-in browser suite (`e2e/saml`, `make e2e`) runs with the Tales binary
and Chrome; it adds no Go dependency.

## Local development

```sh
make sync         # go work sync
make build        # build all modules
make generate     # mockery mocks: in-package mock_*_test.go files, never committed
make test         # generate, then race + coverage, aggregated into build/coverage.out
make lint         # golangci-lint (tools/golangci-lint) on every module with the shared config
make vuln         # govulncheck -test on every module, outside the workspace
make tidy         # go work sync + go mod tidy on every module and tool + go work sync
make check-modules # one go line, go.work complete, sync no-op, every module on its own (GOWORK=off)
make e2e          # opt-in browser suites (Tales + Chrome), never run by CI
```

The `Makefile` discovers modules dynamically via `find . -name go.mod`
(except the tool modules under `tools/`), so a new sub-module is picked up
automatically as soon as its `go.mod` lands. The tools (golangci-lint,
govulncheck, mockery) are built from their pinned modules into `build/bin`
on first use; mocks are generated before anything that compiles tests.
Example program lines are excluded from the aggregated coverage profile
(their `main()` is not unit-testable); the examples are still built, tested,
and linted.

## CI

The workflows run with a read-only token by default (only the release
`publish` job gets `contents: write`), with every action pinned to a commit
SHA.
- `.github/workflows/go.yml` builds the pinned tools, generates the mocks,
  runs `make check-modules`, `make build`, `make test` and `make lint`
  against every module, and uploads the aggregated coverage to Coveralls
  with goveralls (pinned in `tools/goveralls`).
- `.github/workflows/govulncheck.yml` runs `make vuln` (every module, tests
  included) on every change and weekly.
- `.github/workflows/release.yml` runs when a `vX.Y.Z` or `<module>/vX.Y.Z`
  tag is pushed. A read-only job verifies it (`scripts/release-check.sh`,
  `check-modules`, build, test, lint, govulncheck on the released module),
  then a separate job publishes the GitHub release
  ([docs/releasing.md](docs/releasing.md)).
- Dependabot proposes updates for every workspace module (go.work mode), the
  tool modules and the actions, after a 7-day cooldown.

## Replace directives

Every sub-module declares `replace github.com/hyperscale-stack/security => ../`
(`=> ../../` for `oidc/provider` and `internal/integrations`, `=> ../../../`
for the OAuth2 SQL/Redis stores and the interop modules, `=> ../../../../`
for the OIDC client and SAML SP stores), plus one for each in-repo module
of its graph,
so local development and CI work without published versions. Releases are
cut per module with `module/vX.Y.Z` tags (`vX.Y.Z` for the core). Consumers
ignore these `replace` directives, so the in-repo requirements keep the
`v0.0.0-00010101000000-000000000000` placeholder only until a module's first
release: the release commit sets them to the released versions, and
`make release-check` builds each tagged module the way a consumer resolves
it (see [docs/releasing.md](docs/releasing.md)).

## Breaking changes before the first release

No module is tagged yet (the first release of every module is `v1.0.0`),
but code tracking `master` may already rely on its behavior. Each entry
below states what changed and how to adapt.

### `oauth2`: `/introspect` only answers confidential clients (#81)

`/introspect` used to answer any caller the shared `ServerConfig.ClientAuth`
chain authenticated. RFC 7662 §2.1 / §4 require the authorization server to
authenticate the protected resources calling it, but a `client_id` alone is
not a credential (RFC 6749 §2.2), and the authorization server MUST NOT rely
on a public client's authentication to identify it (RFC 6749 §2.3). Yet a
public client's `client_id`, shipped inside every copy of a SPA or mobile
app, was enough for anyone to read the validity and claims of a token they
held, refresh tokens included: through the `none` method, or through
`client_secret_basic` / `client_secret_post` with the client's registered
secret (Basic: even an empty one), whether or not `none` was registered.
Untyped clients authenticating through Basic or Post were answered too.

The endpoint now answers only callers whose `Client.Type()` is
`oauth2.ClientConfidential`: a caller whose credentials are valid but whose
type is anything else gets `401 invalid_client`
(`introspection requires confidential client authentication`):

| Caller at `/introspect`                                                                      | Before              | After                |
| -------------------------------------------------------------------------------------------- | ------------------- | -------------------- |
| Public client via `none` (`client_id` only)                                                  | `200`, token claims | `401 invalid_client` |
| Public client via `client_secret_basic` / `_post` with its secret (Basic: even an empty one) | `200`, token claims | `401 invalid_client` |
| Untyped client via `client_secret_basic` / `_post`                                           | `200`, token claims | `401 invalid_client` |
| Confidential client via `client_secret_basic` / `_post`                                      | `200`, token claims | unchanged (see 3.)   |

`/token` and `/revoke` are unchanged: a public client keeps running the
authorization-code + PKCE flow, refreshing and revoking its own tokens with
`none`.

To migrate:

1. Register every resource server that calls `/introspect` as a confidential
   client with a secret, authenticated with `client_secret_basic` or
   `client_secret_post`. An untyped client — such as an
   `oauth2.DefaultClient` without `TypeValue` — must now set
   `TypeValue: oauth2.ClientConfidential` to keep introspecting.
2. Stop calling `/introspect` from public applications: read `expires_in`
   and `scope` from the `/token` response, or ask a confidential backend.
3. When several resource servers or tenants share the authorization server,
   set `ServerConfig.IntrospectionPolicy`: without one, any authenticated
   confidential client may introspect any token. RFC 7662 §4 says protected
   resources SHOULD be specifically authorized, and when a token can be used
   only at certain resource servers, the authorization server MUST determine
   whether it can be used at the one making the call. A denial answers a bare
   `{"active":false}`, the same bytes as an unknown token; a policy error
   fails closed the same way and reaches `OnError`, so wire both. A typical
   policy discloses access tokens to the resource server they are meant for,
   and refresh tokens to none:

   ```go
   srv, err := oauth2.NewServer(oauth2.ServerConfig{
       // ...
       OnError: onError, // an oauth2.ErrorHook: policy failures are reported here
       IntrospectionPolicy: func(_ context.Context, caller oauth2.Client, tok oauth2.IntrospectedToken) (bool, error) {
           // A refresh token is meant for its client alone and carries no
           // audience: never disclose it to a resource server.
           if tok.Kind != oauth2.TokenKindAccess {
               return false, nil
           }

           // audienceOf is your registry: resource server -> its audience.
           // An empty audience, on either side, fails closed.
           return tok.Audience != "" && tok.Audience == audienceOf(caller.ID()), nil
       },
   })
   ```

   Do not reduce the check to `caller.ID() == tok.ClientID`: the resource
   server introspecting a token is usually not the client it was issued to,
   so that rule refuses the legitimate calls without enforcing any resource
   or tenant boundary. The policy only sees active tokens, only after the
   caller authenticated as a confidential client, and gets the request
   context; see the `oauth2.IntrospectionPolicy` godoc for the full
   contract.

### `oauth2`: atomic token pairs, authoritative token families (#82)

Refresh-token reuse detection promised to revoke the whole token family,
but no store could guarantee it: revocation searched and purged the
family's tokens non-atomically, nothing stopped a rotation or an issuance
racing it, a reuse whose revocation failed was reported as a success, and
the grants persisted an access token before the rest of the exchange could
fail. Every store now keeps one authoritative state per token family —
active or revoked — that issuance, rotation and lookups go through, and
writes each token pair in one atomic call. The guarantees are stated on the
`oauth2.Storage` godoc and checked by `oauth2/storetest`.

| Before                                                                    | After                                                                                                      |
| ------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `SaveAccessToken(ctx, at)`                                                | `SaveTokenPair(ctx, &oauth2.TokenPair{Access: *at})`                                                       |
| `SaveAccessToken` then `SaveRefreshToken` for one issuance                | one `SaveTokenPair(ctx, &oauth2.TokenPair{Access: at, Refresh: &rt})`                                      |
| `SaveAccessToken`, then `RotateRefreshToken(ctx, oldHash, nextRefresh)`   | one `RotateRefreshToken(ctx, oldHash, &oauth2.TokenPair{Access: at, Refresh: &rt})`                        |
| `RevokeRefreshFamily` purges the family's tokens                          | records the family revoked, even before its first token; `""` and IDs over 64 bytes are refused            |
| a token of a revoked family: access token deleted, refresh token consumed | `LookupAccessToken` fails with `invalid_grant` (`ErrTokenFamilyRevoked`); the refresh token reads consumed |
| a reuse returns `ErrRefreshTokenReused` whatever its revocation did       | the error also wraps `ErrTokenFamilyRevocationFailed` when the revocation failed                           |

To migrate:

1. **Wiring.** `ServerConfig.Storage` and the `Storage` of every grant MUST
   be the same store: access and refresh tokens now share one backend (only
   authorization codes may live elsewhere).
2. **Custom stores.** Implement the new methods as the `oauth2.Storage`
   godoc describes, refuse what `TokenPair.Validate` rejects — and a
   rotation without a refresh token — before any I/O, return the `oauth2`
   sentinels as-is or wrapped with `%w` (a `WithDescription` copy no longer
   matches `errors.Is`), and pass `storetest.RunConformance`.
3. **Code seeding tokens** (tests, fixtures) calls `SaveTokenPair`; a
   consumed refresh token can only come from a real `RotateRefreshToken`.
4. **SQL.** Run `Store.Migrate` (or apply `Schema`) once: it creates the
   `oauth2_token_families` table and leaves the existing tables untouched.
   The `idx_oauth2_access_family` and `idx_oauth2_refresh_family` indexes
   are no longer created or used; dropping them is optional. Schedule the
   expired-row cleanup the `store/sql` package documentation describes, and
   never delete a family row before its `expires_at`: an issuance into a
   family whose revoked row is gone records it active again.
5. **Redis.** Families now live in `<prefix>fam:{id}` keys (`<prefix>` being
   the `WithKeyPrefix` value, `oauth2:` by default); the store ignores the
   former `<prefix>famrt:*` and `<prefix>famat:*` sets, which you may delete
   with `SCAN`. The store requires Redis 6.0 or later, a standalone server
   or a Sentinel primary, reads from the primary only, and
   `maxmemory-policy noeviction`: an evicted revoked family can be
   recorded active again by an issuance into it.
6. **Tokens issued before the upgrade.** Upgrading invalidates every
   outstanding refresh token and every access token bound to a family:
   their family has no record, and the stores treat an unknown family as
   revoked. Users re-authenticate; expect a one-off burst of `invalid_grant`
   ("refresh token reused") answers as clients present their pre-upgrade
   refresh tokens. Access tokens outside a family (`client_credentials`,
   implicit) keep working until they expire. Flushing the old token rows
   or keys is good hygiene: they can no longer be used.

### `oauth2`: consumed authorization codes are retained (#80)

`ConsumeAuthorizationCode` deleted a code as it consumed it, so a replay
looked exactly like an unknown code and nothing was left to tie the code
to the tokens its first exchange issued — while RFC 6749 §4.1.2 says those
tokens SHOULD be revoked. Stores now keep a consumed code — flagged
consumed, without the raw code — at least until it expires, and answer a
replay with an `*oauth2.CodeReplayError` carrying the retained record.

| Before                                                      | After                                                                                                                                           |
| ----------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `ConsumeAuthorizationCode` deletes the code                 | flags it consumed and keeps it at least until `ExpiresAt`: Redis until the key expires, SQL until your cleanup, memory for the process lifetime |
| a replay returns `ErrCodeAlreadyUsed`, like an unknown code | a replay returns an `*oauth2.CodeReplayError` (it matches `ErrCodeAlreadyUsed`) carrying the record                                             |
| the memory store keeps the raw `Code`                       | no store keeps it                                                                                                                               |

To migrate:

1. **Custom stores.** Keep a consumed code, without its raw value, at
   least until its `ExpiresAt`. Return the record, with a `nil` error, to
   one caller only; return `nil` and `&oauth2.CodeReplayError{Record: rec}`
   to every later or concurrent caller, and `oauth2.ErrCodeAlreadyUsed` for
   an unknown code. Pass `storetest.RunConformance`.
2. **Code calling `ConsumeAuthorizationCode`** — decorators, custom
   grants — tests `err` first and never issues tokens from a record that
   comes with an error. A wrapper must propagate `err` unchanged or
   wrapped with `%w`, which keeps the replay record reachable through
   `errors.As`: normalizing it to `ErrCodeAlreadyUsed` silently disables
   the revocation a replay triggers.
3. **SQL.** `oauth2_auth_codes` gains a `consumed` column, which `Migrate`
   does not add to an existing table (it only creates missing tables).
   Until it exists, every code exchange fails with `server_error`. Run, on
   PostgreSQL, MySQL or SQLite:

   ```sql
   ALTER TABLE oauth2_auth_codes ADD COLUMN consumed SMALLINT NOT NULL DEFAULT 0;
   ```

   or drop the table and run `Migrate` again: a code only lives
   `AuthorizeConfig.CodeTTL` (10 minutes by default). Consumed codes now
   stay until your cleanup deletes the rows past `expires_at` (see the
   `store/sql` package documentation); index `expires_at` through your
   migration tool.
4. **Redis and memory** need nothing: a code payload without the new
   `consumed` flag is an unconsumed code.
5. **Upgrade every instance at once.** An instance still running an
   earlier build ignores the flag and would accept a code an upgraded
   instance already consumed — a second use of the code.

### `oauth2`: `/revoke` answers 503 when a revocation may have failed (#82)

`/revoke` answered `200 OK` whatever happened, telling the client its token
could no longer be used (RFC 7009 §2.1) even when the store had failed to
revoke it. It now answers `503 temporarily_unavailable`
(`{"error":"temporarily_unavailable","error_description":"revocation temporarily unavailable"}`)
when a token lookup fails for another reason than an unknown token, when
the token's family cannot be revoked, or when a token outside any family
cannot be deleted. RFC 7009 §2.2.1: the client must then assume the token
still exists, and may retry after a delay — revocation is idempotent, so
retrying is safe. An access token is revoked through its family first and
only then deleted: a failed family revocation leaves it in place for the
retry, while a failed delete after the family was revoked is reported but
answers `200 OK`, the token being unusable through its family. Clients that
ignored the status of `/revoke` should now retry on 503.

Unknown tokens and other clients' tokens still answer `200 OK`. Every
underlying failure still reaches `ServerConfig.OnError` exactly once, as a
`server_error` carrying its cause (a failed lookup is now reported too, as
`revoke: token lookup failed`); the 503 itself is not reported again.

### `oauth2`: `client_secret_basic` refuses an empty secret (#94)

`client_secret_basic` decoded `Authorization: Basic base64("<client_id>:")`
into an empty secret and handed it to the client's `SecretMatcher`, and
`DefaultClient.SecretMatches` matched it against an empty `Secret`: anyone
knowing the `client_id` of a client registered without a secret
authenticated as it at `/token` and `/revoke`, and at `/introspect` when the
client was confidential. An empty secret is no credential. RFC 6749 §2.3
lets the authorization server accept the client authentication "meeting its
security requirements" and forbids relying on a public client's
authentication to identify it, and §10.1 forbids issuing client passwords
to native or user-agent-based clients. RFC 6749 §2.3.1 and Appendix A.2
(`client-secret = *VSCHAR`) allow an empty secret on the wire, but they do
not oblige the server to accept one: Basic is required "for authenticating
clients that were issued a client password", and a client registered
without a secret was issued none.

`client_secret_basic` now refuses a missing `client_id` or an empty
password with `401 invalid_client` (`missing client_id or client_secret`)
before loading the client, as `client_secret_post`'s `Authenticate`
already did (a form with an empty `client_secret` is a `none` request),
and `DefaultClient.SecretMatches` never matches an empty `Secret`:

| Request                                                        | Before                                                   | After                           |
| -------------------------------------------------------------- | -------------------------------------------------------- | ------------------------------- |
| Basic, empty password, client registered without a secret      | authenticated (`/introspect`: confidential clients only) | `401 invalid_client`            |
| Basic, empty password, client with a secret, or unknown client | `401`, description depends on the client                 | `401`, same description for all |
| Basic/Post with a real secret; `none` for public clients       | authenticated                                            | unchanged                       |
| `DefaultClient{Secret: ""}.SecretMatches("")`                  | `true`                                                   | `false`                         |

To migrate:

1. **Public clients that sent an empty Basic password** use `none`
   instead: `client_id` in the form body, no `Authorization` header and no
   `client_secret` (RFC 6749 §3.2.1). Register them with
   `TypeValue: oauth2.ClientPublic`, add `clientauth.NewNone()` to
   `ServerConfig.ClientAuth` (`examples/oauth2` does not wire it) and, if
   the client sets `AuthMethodValues`, include `"none"`.
2. **Confidential or untyped clients registered without a secret** can no
   longer authenticate through `client_secret_basic` or
   `client_secret_post` (and `none` refuses non-public clients). Give each
   one a high-entropy secret, or authenticate it with a custom
   `ClientAuthenticator` using another credential (e.g. `private_key_jwt`,
   mTLS). Register a client as public only if it cannot keep a secret — a
   browser or native app using `authorization_code` + PKCE — and then set
   its `GrantTypeValues` (an empty list allows no grant; see "a client gets
   only what it declares and what it asked for" below).
3. **Custom `SecretMatcher`s** must return `false` when no secret is
   registered or the presented one is empty, whatever they compare
   against: a bcrypt hash of `""` matches `""`.

### `oauth2`: codes and tokens are bound to their issuer and record extension data (#83)

An authorization code was not bound to the realm that authorized it:
`/token` resolved the issuer again, so behind an `IssuerResolver` serving
several realms (per `Host` or path) a client could redeem a code authorized
at one issuer, or refresh a token issued there, at another one — obtaining
tokens of realm B for a subject of realm A, while a subject is only
meaningful within its issuer (OIDC Core §16.15). And nothing could carry the
authentication context an OpenID Connect provider needs from `/authorize` to
the token response and through refreshes. Codes and tokens now record the
issuer they were issued under and the opaque grant context of an
`oauth2.Extension`; the grants refuse a code or refresh token at another
issuer, and a rotation never changes the context it carries.

| Before | After |
| ------ | ----- |
| `/authorize` resolved no issuer for the code flow (the implicit flow did, after the consent) | resolves it right after the redirect URI is trusted, for both flows: a resolver failure answers a redirected `server_error`, before the `ConsentFunc` runs; `AuthorizeRequest.Issuer` exposes it |
| a code or refresh token redeemed at any issuer | `invalid_grant` (`authorization code issued by another issuer`, `refresh_token issued by another issuer`); a refused refresh consumes nothing, a code replayed at another issuer revokes nothing |
| `AuthorizationCode`, `AccessToken`, `RefreshToken` | gain `Issuer` and `ExtensionData` (strings every store persists byte-exact); `IntrospectedToken` gains `Issuer` |
| codes and refresh tokens written before the upgrade | carry no issuer: refused with `invalid_grant` unless your resolver returns an empty issuer — fail closed |
| `TokenPair.Validate` | also refuses a refresh token whose `Issuer` or `ExtensionData` differ from its access token's (`invalid_request`) |
| `RotateRefreshToken` accepted any replacement in the family | refuses with `invalid_request`, writing nothing, a replacement whose `Issuer` or `ExtensionData` differ from the presented token's (checked right after the family) |

To migrate:

1. **Issuer resolution.** An `IssuerResolver` MUST return the same issuer
   for every request of one realm — `/authorize` and `/token` — and issuers
   are compared exactly. Renaming an issuer invalidates the outstanding codes
   and refresh tokens issued under the former one.
2. **SQL.** The three code and token tables gain two nullable `TEXT`
   columns, which `Migrate` does not add to an existing table (it only
   creates missing tables; new installs get them). Until they exist, every
   code and token write and lookup fails with `server_error`. Apply, through
   your migration tool and before the new build serves traffic — the same
   statements on PostgreSQL, MySQL and SQLite:

   ```sql
   ALTER TABLE oauth2_auth_codes     ADD COLUMN issuer TEXT;
   ALTER TABLE oauth2_auth_codes     ADD COLUMN extension_data TEXT;
   ALTER TABLE oauth2_access_tokens  ADD COLUMN issuer TEXT;
   ALTER TABLE oauth2_access_tokens  ADD COLUMN extension_data TEXT;
   ALTER TABLE oauth2_refresh_tokens ADD COLUMN issuer TEXT;
   ALTER TABLE oauth2_refresh_tokens ADD COLUMN extension_data TEXT;
   ```

   A row written before them reads an empty issuer and extension data, and is
   refused at `/token` (step 4). A deployment with a **single** issuer can
   keep its users signed in by stamping that issuer — exactly the value its
   `IssuerResolver` returns — on the existing rows, after the `ALTER`s and
   before serving traffic:

   ```sql
   UPDATE oauth2_auth_codes     SET issuer = 'https://auth.example' WHERE issuer IS NULL;
   UPDATE oauth2_access_tokens  SET issuer = 'https://auth.example' WHERE issuer IS NULL;
   UPDATE oauth2_refresh_tokens SET issuer = 'https://auth.example' WHERE issuer IS NULL;
   ```

   A multi-issuer deployment must not backfill: nothing tells which realm a
   row belongs to. Keep PostgreSQL databases in `UTF8` and MySQL tables in
   `utf8mb4` with a strict `sql_mode` (see the `store/sql` package
   documentation).
3. **Redis and memory** need nothing: the new payload fields are additive,
   and a payload without them reads an empty issuer and extension data.
4. **Codes and tokens issued before the upgrade.** Outstanding codes (they
   live `AuthorizeConfig.CodeTTL`, 10 minutes by default) and refresh tokens
   carry no issuer and are refused with `invalid_grant`: users
   re-authenticate, unless the SQL backfill of step 2 applies. Access tokens
   keep working until they expire.
5. **Upgrade every instance at once.** An instance still running an earlier
   build writes codes and tokens without an issuer, which upgraded instances
   refuse, and checks no issuer itself.
6. **Custom stores** persist and return `Issuer` and `ExtensionData` on the
   three records byte-exact — the record of a `*oauth2.CodeReplayError` and
   consumed refresh tokens included — read a missing value as `""`, refuse
   in `RotateRefreshToken` a replacement carrying another issuer or extension
   data (`invalid_request`, after the family check), and pass
   `storetest.RunConformance`.
7. **Custom grants** stamp the tokens they mint with `GrantRequest.Issuer`
   and the `ExtensionData` of the code or refresh token they redeem, after
   checking its `Issuer` against `GrantRequest.Issuer`. **Code seeding codes
   or tokens** (tests, fixtures) sets their `Issuer` to the issuer the
   requests resolve.

### `oauth2`: `/authorize` refuses unsupported response modes and approvals without a subject (#83)

`/authorize` ignored `response_mode`: a client asking for a mode the server
does not serve still got its answer — code or error — in the query string,
where it did not expect it; the response mode decides how every answer
travels, and one the server cannot honor leaves no way to answer at all
(OAuth 2.0 Multiple Response Type Encoding Practices §2.1; OIDC Core 1.0
incorporating errata set 2, §3.1.2.6). An approval without a subject,
documented as required, was never refused. And a `ConsentFunc` could not
answer a protocol refusal such as OpenID Connect's `login_required`.

| Request | Before | After |
| ------- | ------ | ----- |
| `response_mode` absent or empty, `query` (code flow), `fragment` (enabled implicit flow) | served | unchanged |
| any other `response_mode` — `fragment` for the code flow, `query` for the implicit one, `form_post`, a case variant, an unknown value | ignored, answered in the default mode | bare `400` (`text/plain`, never redirected), reported to `OnError` as `invalid_request`, before any other check that would redirect |
| RFC 8414 metadata | no `response_modes_supported`, which means `["query", "fragment"]` (RFC 8414 §2) | `"response_modes_supported": ["query"]`, the mode of the advertised `code` response type |
| approval with an empty `Subject`, or one longer than 255 bytes | code or token issued | redirected `server_error`, nothing issued |
| `ConsentFunc` or extension hook modifying the `*AuthorizeRequest` it is handed (scope, redirect URI, state, PKCE, nonce, issuer, client identity) | the server read the rewritten request back: rewriting `ar.Scope` narrowed — or broadened — the grant | redirected `server_error` (`ErrAuthorizeRequestModified` at `OnError`), nothing issued; the request is read-only |
| denial carrying `Consent.Refusal` | — (field new) | `Refusal` redirected instead of `access_denied`; only the RFC 6749 §4.1.2.1 and OIDC Core §3.1.2.6 authorization-endpoint codes travel, any other answers `server_error` |
| approval carrying a `Refusal` | — | `server_error` (contradiction, fail closed) |
| `ConsentFunc` returning `(nil, err)` | `server_error` | unchanged, whatever `err` — an `*oauth2.Error` included; the cause now reaches `OnError` |
| `invalid_scope` / `unsupported_response_type` descriptions | echoed the request (`scope "x" is not allowed for this client`) | fixed text, never echoing the request |

To migrate:

1. Clients sending `response_mode` send nothing, or the default mode of
   their response type; `form_post` is not supported.
2. `ConsentFunc`s name the resource owner in `Consent.Subject` — at most 255
   bytes (OIDC Core §2) — on every approval, and treat the
   `*AuthorizeRequest` they are handed as read-only: narrow the grant with
   `Consent.Scope`, never by rewriting `ar.Scope` — the authorization would
   now fail with `server_error`.
3. A `ConsentFunc` refusing with a protocol code returns
   `&oauth2.Consent{Refusal: oauth2.ErrLoginRequired}` (or
   `ErrConsentRequired`, `ErrInteractionRequired`, … `access_denied` stays
   the default). Its `Description` and `URI` reach the client's URL,
   history and logs: never put personal data in them.

### `oauth2`: error responses keep to the RFC 6749 syntax (#83)

The error responses carried whatever a grant, or the server itself, put in
an `*oauth2.Error`, although RFC 6749 §4.1.2.1 and §5.2 restrict codes and
descriptions to `%x20-21 / %x23-5B / %x5D-7E` and `error_uri` to
`%x21 / %x23-5B / %x5D-7E`. Errors that do not come from the server itself —
a grant's, an extension's, a `Consent.Refusal` — are now held to that syntax:

| Error | Before | After |
| ----- | ------ | ----- |
| code empty or outside the charset (`/token`, `/revoke`, `/introspect`) | written as is | `server_error`; the original reaches `OnError` as its cause |
| code the authorization endpoint does not define, at `/authorize` | — (only the server's codes were redirected) | `server_error` |
| `error_description` outside the charset | written as is | left out, the code kept |
| `error_uri` outside the charset, or not a URI reference | written as is (`/authorize`: never sent) | left out; a valid one is now redirected too |

Nothing to do unless a custom grant relied on such values: keep codes,
descriptions and URIs within the RFC 6749 syntax — a localized description
with accents is dropped.

### `oauth2`: protocol extension points; `GrantResponse.ExtraParams` removed (#83)

`GrantResponse.ExtraParams` was never serialized: a grant setting it changed
nothing on the wire. It is removed. The members a token response may carry
are fields, so nothing can shadow `access_token`, `token_type`,
`expires_in`, `refresh_token` or `scope`; `GrantResponse.IDToken` is the one
an `oauth2.Extension` adds (`id_token`, OIDC Core §3.1.3.3).

| Before | After |
| ------ | ----- |
| `GrantResponse.ExtraParams map[string]any` (dropped) | removed; `GrantResponse.IDToken` (serialized when non-empty) |
| no way to extend the authorization-code flow | `ServerConfig.Extension` (`oauth2.Extension`): `ValidateAuthorizeRequest`, `CompleteAuthorization`, `ExtendTokenResponse` (its `TokenIssuance` carries the access token, the grant context, the nonce and `RefreshTokenIssued`); `AuthorizeRequest.ExtensionRequest`, `Consent.ExtensionResult`; `GrantRequest.Extension` |
| a refresh token with every code exchange that has a generator | unchanged by default; `grant.Config.RefreshTokenScope` (e.g. `offline_access`, OIDC Core §11) issues one only when the grant holds that scope |

To migrate:

1. Drop `ExtraParams` assignments (they had no effect); an id_token goes in
   `IDToken`.
2. Grant decorators forward the `GrantRequest` unchanged — `Extension`
   included — and custom grants redeeming an authorization call
   `GrantRequest.Extension.ExtendTokenResponse` between minting their tokens
   and persisting them, or answer without its members.
3. Without an extension, nothing changes on the wire.

### `oauth2`: `client_secret_basic` form-decodes the client credentials (#84)

RFC 6749 §2.3.1 encodes the `client_id` and the `client_secret` with the
`application/x-www-form-urlencoded` algorithm (Appendix B) before they become
the HTTP Basic user-id and password. `client_secret_basic` compared them
undecoded, so a compliant client whose identifier or secret holds a reserved
or non-ASCII character — e.g. `golang.org/x/oauth2` with `AuthStyleInHeader`,
which sends `url.QueryEscape(secret)` — was answered `invalid_client`. The
credentials are now split at the first colon of the decoded header (an
encoded colon, `%3A`, belongs to its value) and each part is form-decoded:

| Basic credentials (after Base64)                    | Before                             | After                                                   |
| --------------------------------------------------- | ---------------------------------- | ------------------------------------------------------- |
| unreserved characters only (`A-Z a-z 0-9 - . _ ~`)  | authenticated                      | unchanged                                               |
| encoded reserved characters (`p%40ss%2Bw%3Ard`)     | compared encoded: `invalid_client` | decoded (`p@ss+w:rd`): authenticated                    |
| unencoded `+` in the secret (`a+b`)                 | compared as is                     | decoded as a space (`a b`): `invalid_client`            |
| invalid escape (`50%zz`, a lone `%`)                | compared as is                     | `401 invalid_client` (`malformed Basic Authorization header`), client not loaded |
| empty client_id or secret once decoded              | `401 invalid_client` (#94)         | unchanged                                               |

`client_secret_post` is unaffected (the form body was always decoded).

To migrate:

1. Clients authenticating with `client_secret_basic` encode their
   `client_id` and `client_secret` with `application/x-www-form-urlencoded`
   before Base64 (RFC 6749 §2.3.1) — `url.QueryEscape` in Go. A client whose
   credentials only use unreserved characters needs no change: secrets
   generated as base64url or hex are unaffected.
2. A client that sends a secret holding `%` or `+` unencoded now fails:
   encode it, switch it to `client_secret_post`, or rotate it to unreserved
   characters.

### `oauth2`: authorization responses name the issuer (RFC 9207, #84)

A client talking to several authorization servers — or to several realms of
one `IssuerResolver` — could not tell which one answered its authorization
request, the precondition of a mix-up attack (RFC 9700 §4.4). Every
authorization response now carries `iss`, the issuer identifier the request
resolved to (RFC 9207 §2), and the RFC 8414 metadata publishes
`authorization_response_iss_parameter_supported: true` (§3):

| Response                                              | Before                  | After                                   |
| ----------------------------------------------------- | ----------------------- | --------------------------------------- |
| code (query)                                          | `code`, `state`         | `code`, `state`, `iss`                  |
| implicit (fragment)                                   | token members, `state`  | token members, `state`, `iss`           |
| redirected error (consent, extension, core checks)    | `error`…, `state`       | `error`…, `state`, `iss`                |
| `server_error` when the `IssuerResolver` fails        | `error`, `state`        | unchanged (no issuer is known)          |
| bare 400 answers (client, redirect URI, response mode) | not redirected          | unchanged                               |

To migrate:

1. Nothing for clients that do not know RFC 9207: RFC 6749 §4.1.2 requires
   them to ignore unrecognized response parameters.
2. RFC 9207 clients compare `iss` with the issuer of the authorization server
   they sent the request to (simple string comparison) and reject a mismatch
   — the issuer the `IssuerResolver` returns must be exactly the one the
   metadata publishes, an https URL without query or fragment.

### `jwt`: RFC 9068 access tokens are typed `at+jwt` and carry a `jti` (#84)

`jwtsec.NewOAuth2AccessTokenSigner` claimed RFC 9068 but signed with
`typ: JWT` and without `jti`, although RFC 9068 §2.1 requires `typ: at+jwt` —
the explicit type that keeps an OpenID Connect ID Token from being accepted
as an access token (RFC 9068 §4, RFC 8725 §3.11) — and §2.2 makes `jti`
REQUIRED. It also wrapped any `Signer`, so nothing guaranteed the header.

| Before | After |
| ------ | ----- |
| `NewOAuth2AccessTokenSigner(signer Signer)` | `NewOAuth2AccessTokenSigner(key PrivateKey)`: builds its own signer, typed `at+jwt`; panics on a key without `Algorithm` or `Key`, like `NewSigner` |
| access tokens `typ: JWT`, no `jti` | `typ: at+jwt`, a random 128-bit base64url `jti` per token |
| `NewSigner(key, opts...)` ignored every option | honours `WithType` (the `typ` it writes, `JWT` by default); still ignores verifier options |
| no `typ` check | `WithType(t)` on a verifier requires `typ` ≡ `t` (RFC 7515 §4.1.9: case-insensitive, `application/` implied) — `ErrInvalidType` otherwise; opt-in |

To migrate:

1. Pass the `jwtsec.PrivateKey` to `NewOAuth2AccessTokenSigner` instead of a
   `Signer` built from it. A custom `Signer` (e.g. KMS-backed) implements
   `token.AccessTokenSigner` itself, typing its tokens `at+jwt` and adding a
   `jti`.
2. Resource servers verifying these access tokens add
   `jwtsec.WithType(jwtsec.TypeAccessToken)` to their verifier (RFC 9068 §4).
   A verifier that compared `typ` with `JWT` must accept `at+jwt` now.

### `jwt`: keys print, log and encode without their material (#86)

A `jwtsec.PrivateKey` holding an Ed25519 or HMAC key — or an HMAC secret
carried as a `PublicKey` — printed its material with `fmt`, and so did a
`Signer` or a static key set holding one; `encoding/json` wrote the material
of every private key, so `slog`'s JSON handler logged it:

| | Before | After |
| --- | --- | --- |
| `fmt` of a key, a `Signer`, a `NewStaticJWKS` provider or key set, a `Verifier`, an `OAuth2AccessTokenSigner` | Ed25519 and HMAC key bytes (`%v` and most verbs) | key IDs, algorithm and key type, e.g. `jwtsec.PrivateKey{KeyID: "k1", Algorithm: EdDSA, Key: ed25519.PrivateKey REDACTED}`, whatever the verb |
| `log/slog` of a key | its fields | `kid`, `alg` and the key type |
| `encoding/json` of a `PrivateKey` or an HMAC `PublicKey` | the key material | `{"KeyID": …, "Algorithm": …, "Key": "<key type> REDACTED"}` |
| `encoding/json` of an asymmetric `PublicKey` | its public fields | unchanged |

Nothing to migrate unless code serialized private keys with `encoding/json`
— it could not read them back (`Key` is an interface). Publish public keys
with `MarshalJWKS`; keep private keys in a secret store.

### `oauth2`: clients can be bound to the issuers they are registered at (#84)

With one `ClientStore` behind an `IssuerResolver` that serves several
issuers (realms, tenants), every client was known at every issuer: a client
of realm A could send the end-users of realm B to B's login page and obtain
their codes and tokens, and an ID Token of B for its own audience. A client
can now be registered at some issuers only: `oauth2.IssuerBoundClient`
(`AllowsIssuer(issuer string) bool`), implemented by `DefaultClient` through
`IssuerValues` — an empty list keeps the client at every issuer. At any other
issuer the client does not exist:

| Request at an issuer the client is not registered at | Before | After |
| ---------------------------------------------------- | ------ | ----- |
| `/authorize` | served like at its own issuer | bare `400` "unknown or invalid client", never redirected — the same bytes as for a `client_id` that exists nowhere (RFC 6749 §4.1.2.1) |
| `/token`, `/revoke`, `/introspect` | authenticated | `401 invalid_client` "unknown client", whatever the secret — the same answer as for an unknown client (RFC 6749 §5.2) |
| any of them | — | `OnError` gets the refusal with `oauth2.ErrClientNotAtIssuer` as its cause |

The server now resolves the issuer of a request before it loads its client:

| Endpoint | Before | After |
| -------- | ------ | ----- |
| `/authorize` | the `IssuerResolver` ran once the redirect URI was trusted | it runs first; a failure is still answered with a redirected `server_error` without `iss` once the redirect URI is trusted |
| `/token` | client authentication and `grant_type` checks before the resolver | the resolver first: when it fails, `server_error` wins over every other error |
| `/revoke`, `/introspect` | no `IssuerResolver` call | the resolver runs before client authentication; a failure answers `500 server_error` |

To migrate:

1. Nothing for clients that do not implement `IssuerBoundClient`, nor for a
   `DefaultClient` without `IssuerValues`: they keep working at every issuer.
2. Make your `IssuerResolver` answer every endpoint of a realm — `/revoke`
   and `/introspect` included — with the issuer of that realm.
3. In a deployment serving several issuers from one `ClientStore`, give
   every client the issuers it is registered at: implement `AllowsIssuer` on
   your client type (issuers compared exactly), or fill
   `DefaultClient.IssuerValues` — or scope your `ClientStore` by issuer.

### `oidc/client`: a server-held key protects the login transactions (#86)

The integrity MAC of a `Transaction` (#85) was keyed by the login's binding
secret only. The user agent that starts a login holds that secret, so an
attacker with write access to the transaction store could start a login in
its own browser, strip its `max_age` or `acr_values` requirement — a step-up
or MFA bypass — or rewrite its `AppState`, recompute the MAC and complete the
login. The MAC key now also requires a server-held transaction key the store
never sees:

| | Before | After |
| --- | --- | --- |
| `Config.TransactionKeys` | — | REQUIRED: 1 to 4 keys of at least 32 bytes; `New` fails with `ErrInvalidConfig` otherwise, before any network access |
| MAC key of a transaction | HMAC-SHA256(binding secret, `"oidcclient/integrity/v1"`) | HMAC-SHA256(transaction key, `"oidcclient/integrity/v2"` ‖ binding secret): `TransactionKeys[0]` for new transactions, any key accepted |
| a store writer relaxing a login it runs itself | login completed | `ErrTransactionIntegrity`, the code is never redeemed |
| transactions stored before the upgrade | — | fail once with `ErrTransactionIntegrity` (the user signs in again) |
| SQL and Redis stores | — | unchanged: `Integrity` is still 64 hex digits |
| `fmt` / `log/slog` of a `Config` or a `*Client` | every field, client secret included | identifying fields only, with every `fmt` verb; client secret and keys redacted |

To migrate:

1. Generate a transaction key: 32 bytes or more from a cryptographic source
   (`openssl rand -hex 32`). It is a secret like a session key: keep it in
   your secret store, never in code or logs.
2. Give the same keys to every instance that may serve a callback, and set
   `Config.TransactionKeys: [][]byte{key}` on every `oidcclient.Client`
   (`examples/oidc-client` reads `OIDC_TRANSACTION_KEYS`, hex keys separated
   by commas).
3. Deploy knowing that the logins in progress at that moment fail once with
   `ErrTransactionIntegrity`; the users start over.
4. To rotate a key later without failing a login: add the new key last on
   every instance; once all of them run with it, move it first; remove the
   old key once `TransactionTTL` (10 minutes by default) has elapsed.

### `oauth2`: a `code_verifier` without `code_challenge` is refused (PKCE downgrade, #86)

RFC 9700 §4.8.2: "the authorization server MUST ensure that if there was no
code_challenge in the authorization request, a request to the token endpoint
containing a code_verifier is rejected". Under `Profile20`, where PKCE is
optional (unless `grant.Config.RequirePKCE`), `/token` ignored a
`code_verifier` sent for a code issued without `code_challenge`: an attacker
could strip `code_challenge` from its own authorization request and inject the
code into a victim's session at a client that relies on PKCE rather than
`state`.

| Code issued | `code_verifier` in the token request | Before | After |
| --- | --- | --- | --- |
| without `code_challenge`, `Profile20` | absent, or present without a value | issued | unchanged |
| without `code_challenge`, `Profile20` | with a value (any occurrence) | issued, verifier ignored | `400 invalid_grant` ("code_verifier sent for a code issued without code_challenge"); the code is consumed, nothing is issued or revoked |
| without `code_challenge`, `Profile20BCP` / `Profile21Draft` | any | `invalid_grant` ("PKCE required") | unchanged |
| with `code_challenge` | any | verified (RFC 7636 §4.6) | unchanged |
| replay of a code redeemed without PKCE, otherwise valid | with a value | `invalid_grant`, family revoked (#80) | unchanged |

To migrate:

1. Nothing for clients that use PKCE (send `code_challenge`, then
   `code_verifier`) or none of it.
2. A `Profile20` client that sends a `code_verifier` without having sent a
   `code_challenge` now fails: send the matching `code_challenge` (S256) in
   its authorization requests, or stop sending the verifier.

### Toolchain: every module requires Go 1.27.2

Every `go.mod`, and `go.work`, now declares `go 1.27.2`. Since Go 1.21 the
`go` line is a minimum: a module that requires one of ours must declare
`go 1.27.2` or later, and building it needs a go1.27.2 or later toolchain.
The modules used to declare `go 1.26.0` or `go 1.26.5`, and the toolchain CI
tested with (go1.26.5) carries standard-library advisories reachable from
the library's own call paths: HTTP/2 server crashes and request smuggling in
`net/http`, `crypto/tls`, `encoding/asn1`, `net/url`, `encoding/xml`. All of
them are fixed in go1.27.2, on which `govulncheck` reports none.

|                                            | Before                    | After                                                      |
| ------------------------------------------ | ------------------------- | ---------------------------------------------------------- |
| `go` line of every module and of `go.work` | `go 1.26.0` / `go 1.26.5` | `go 1.27.2`                                                |
| Toolchain that builds a consumer           | go1.26.0 or later         | go1.27.2 or later (switched to under `GOTOOLCHAIN=auto`)   |
| Toolchain CI tests and releases with       | go1.26.5                  | go1.27.2, read from `go.work`                              |

Behaviour the Go 1.27 floor brings to every consumer (Go 1.27 release
notes):

- `encoding/json` runs on the `encoding/json/v2` implementation: what is
  marshaled and unmarshaled is unchanged, but error texts may differ, so
  never match on them;
- `net/http`: closing an HTTP/1 `Response.Body` drains the unread content;
- `crypto/x509`: on darwin and windows `SystemCertPool` honours
  `SSL_CERT_FILE` and `SSL_CERT_DIR` (`GODEBUG=x509sslcertoverrideplatform=0`
  restores the platform verifier);
- `compress/flate` (and so `gzip`) output differs from Go 1.26 for the same
  input.

To migrate:

1. Set your module's `go` line to `1.27.2` or later: `go get` of one of our
   modules does it, or run `go mod edit -go=1.27.2`.
2. With `GOTOOLCHAIN=auto` (the default) the go command downloads go1.27.2
   from the module proxy, verified by the checksum database. Where
   `GOTOOLCHAIN=local` (some Linux distributions, hermetic CI), install
   go1.27.2 or later first: an older toolchain stops with
   `go.mod requires go >= 1.27.2`.
3. Build and ship with the latest Go patch release: the `go` line is a
   floor, not the toolchain to release with.

### `oidc/client`: discovery and JWK Set redirects stay on their origin

With `Config.Outbound.MaxRedirects` above zero, the discovery request and
the JWK Set requests followed redirects to any origin. A server at the end of
such a redirect only had to write the configured issuer in its document to
get its own endpoints and keys trusted — OpenID Connect Discovery 1.0 §7.2
relies on TLS to the issuer — and a redirected `jwks_uri` made another
origin's keys verify ID Tokens. Every hop must now stay on the origin —
scheme, host and port — of the URL first requested:

| Redirect, with `MaxRedirects > 0` | Before | After |
| --- | --- | --- |
| discovery, to another host, port or scheme (an http→https redirect on the same host with `AllowHTTP` included) | followed; the document used if its `issuer` matched | `New` fails with `ErrDiscovery` (`outbound.ErrRedirectNotAllowed`) |
| JWK Set, to another origin than the `jwks_uri`'s — the issuer's included | followed; its keys verify ID Tokens | the fetch fails: logins fail with `ErrKeySet` (`outbound.ErrRedirectNotAllowed`) |
| discovery or JWK Set, within the origin requested | followed | unchanged |
| token, UserInfo | never followed | unchanged |
| any, with `MaxRedirects: 0` (the default) | refused | unchanged |

To migrate:

1. Nothing with the default policy (`MaxRedirects: 0`).
2. Configure as `Issuer` the issuer whose own server answers
   `/.well-known/openid-configuration`: metadata redirected to another
   server is no longer used.
3. A provider whose `jwks_uri` redirects to another origin (a CDN, say) must
   publish the final URL as its `jwks_uri`; there is no opt-out.

### `oidc/client`: `AuthRequest`, `Callback` and `Config` encode without their secrets

`fmt` and `log/slog` already printed these types redacted, but
`encoding/json` wrote every exported field: the binding secret of an
`AuthRequest`, the binding secret, authorization code and state of a
`Callback`. `slog`'s JSON handler calls `LogValue` for attribute values only
and encodes a value nested in another one with `encoding/json`, so a login
logged inside a struct revealed them. They now implement `json.Marshaler`,
like `Config`:

| `json.Marshal` of | Before | After |
| --- | --- | --- |
| `AuthRequest` | `{"URL":…,"State":…,"Binding":"<secret>","ExpiresAt":…}` | `{"URL":…,"State":…,"ExpiresAt":…,"Binding":"REDACTED"}` |
| `Callback` | `{"Mode":…,"URL":{…"RawQuery":"code=…&state=…"},"Params":{…},"Binding":"<secret>"}` | `{"Mode":…,"URL":"<URL without query>","Params":<count>,"Binding":"REDACTED"}` |
| `Config` | an error (`json: unsupported type: func…`) | `{"ConnectionID":…,"Issuer":…,"ClientID":…,"ClientSecret":"REDACTED","AuthMethod":…,"RedirectURL":…,"ResponseMode":…,"TransactionKeys":<count>}` |
| a struct **embedding** `AuthRequest` or `Callback` | its own fields and the embedded ones | the promoted `MarshalJSON`: the embedded value's redacted document alone — the struct's other fields are not written; when another type embedded at the same depth also has a `MarshalJSON`, neither is promoted and the exported fields are written, the secrets excluded |
| `json.Unmarshal` into `AuthRequest`, `Callback` | every field read | `AuthRequest.Binding` and `Callback`'s `URL`, `Params` and `Binding` are tagged `json:"-"`: never read nor written by a reflective encoding |
| `Identity`, `Tokens` | tokens and claims | unchanged, deliberately: JSON is how applications persist them |
| `UserInfo` | its claims | unchanged; `fmt` now prints its subject only |
| `*Client` | `{}` | unchanged |

To migrate:

1. Nothing for code that does not encode these types with `encoding/json`.
2. Code that persisted an `AuthRequest` as JSON (a server-side login state)
   must store `AuthRequest.Binding` explicitly, where a secret belongs (an
   HttpOnly cookie, a server-side session): read back from the new JSON, it
   is `REDACTED` and the callback fails with `ErrBindingMismatch`.
3. A struct that embeds `AuthRequest` or `Callback` and is encoded with
   `encoding/json` now encodes as the embedded value alone — or, next to
   another embedded type with a `MarshalJSON`, as flattened fields without
   the secrets: name the field (`Login oidcclient.AuthRequest`) instead of
   embedding it.
4. Other reflection-based encoders (`encoding/gob`, `encoding/xml`, YAML)
   still write the binding secret: do not use them on these types.
5. Keep logging an `Identity` or `Tokens` as an attribute of its own: nested
   in another logged value, `slog`'s JSON handler writes their tokens.

### `oidc/client`: an authorization request never repeats a parameter

RFC 6749 §3.1: "Request and response parameters MUST NOT be included more
than once", and the authorization endpoint's own query "MUST be retained".
`AuthOptions.ExtraParams` names were compared with the parameters the client
sends exactly, and not at all with the endpoint's query, so `Request`,
`STATE` or `request.uri` passed — read as `request`, `state`, `request_uri`
by a provider that ignores case (ASP.NET) or rewrites `.` as `_` (PHP) — and
an entry could repeat a parameter of the endpoint's query. Names are now
compared case-insensitively, with `.` (and, in a provider's query, space and
`[`) read as `_`:

| | Before | After |
| --- | --- | --- |
| `ExtraParams` spelling a parameter the client sends or does not support (`Nonce`, `STATE`, `Request`, `request.uri`, `Redirect.Uri`…) | sent | `Begin` fails with `ErrInvalidAuthRequest`, nothing stored |
| `ExtraParams` naming a parameter of the endpoint's query (`tenant`, `Tenant`, `tenant.id` for `?tenant_id=`) | sent twice | `Begin` fails with `ErrInvalidAuthRequest` |
| two `ExtraParams` that are one parameter (`tenant` and `TENANT`, `a.b` and `a_b`) | both sent | `Begin` fails with `ErrInvalidAuthRequest` |
| an authorization endpoint whose query spells a reserved parameter (`?State=`, `?request.uri=`) or repeats a name (`?tenant=a&TENANT=b`) | used | `New` fails with `ErrInvalidMetadata` |

To migrate:

1. Nothing for `ExtraParams` with distinct, non-reserved names, which are
   sent as before.
2. Remove the entries `Begin` now refuses; a value the provider's
   authorization endpoint already sets in its query cannot be changed per
   login.
3. None of the six providers of the pinned discovery corpus has a query in
   its authorization endpoint; a provider whose query `New` now refuses has
   to fix its metadata.

### `oidc/client/storage/memory`: `New` takes options

`memory.New()` became `memory.New(opts ...memory.Option)`, to accept
`memory.WithCapacity(n)`, which bounds the pending logins the store keeps
(see CHANGELOG, Added). Calls compile and behave as before: without the
option, the store stays unbounded.

| | Before | After |
| --- | --- | --- |
| `memory.New()` | an unbounded store | unchanged |
| `memory.New` used as a `func() *memory.Store` value | compiles | does not compile: its type is `func(...memory.Option) *memory.Store` |

To migrate:

1. Wrap such a use in a closure: `func() *memory.Store { return memory.New() }`.
2. Login starts are unauthenticated: consider
   `memory.New(memory.WithCapacity(n))`, sized as LIMITATIONS.md explains,
   together with rate limiting.

### `oauth2`: scope values are parsed strictly and bounded

Comparing a requested scope with a client's registration, a consent's
narrowing or an extension's narrowing cost a time proportional to the
product of their sizes, and nothing bounded the request: tens of thousands
of scope tokens in one URL took seconds of CPU per `/authorize` request.
Scope values were also split on any Unicode whitespace and, for a client
without `ScopeValues`, accepted with any character. Every scope value a
client or a callback sends — the `scope` of `/authorize` and `/token`,
`Consent.Scope`, `ExtensionGrant.Scope` — is now parsed once, strictly, as
RFC 6749 §3.3 tokens, compared with set lookups, and issued canonical:

| Scope value | Before | After |
| ----------- | ------ | ----- |
| tokens separated by SP (runs of SP, leading or trailing SPs included) | accepted | unchanged |
| separated by TAB, LF or another Unicode space; holding `"`, `\`, a control or a non-ASCII character | split on any whitespace; any character accepted for a client without `ScopeValues` | `invalid_scope` (`ExtensionGrant.Scope`: `server_error`) |
| more than 100 tokens (repetitions included) or 4096 bytes | accepted | `invalid_scope` |
| repeated tokens | kept (`read read`) | dropped: the scope issued and stored is single-SP joined, duplicates dropped (`read`) — `AuthorizeRequest.Scope` included |
| refresh narrowing | returned as sent (a TAB-separated value too) | canonical; a value holding no token keeps the original scope (RFC 6749 §6) |
| `/token` `invalid_scope` description | `scope <token> not allowed for client` | a fixed text that never echoes the request |

To migrate:

1. Clients send scope tokens of printable ASCII without `"` or `\`,
   separated by single spaces — at most 100 of them.
2. Register scopes in that syntax: a registered scope holding a space or a
   non-ASCII character can no longer be requested.
3. A `ConsentFunc` narrowing with `Consent.Scope`, or an `Extension`
   narrowing with `ExtensionGrant.Scope`, joins its tokens with a single
   space.
4. Nothing to do for stored codes and tokens: the server never refuses a
   scope it stored itself.

### `oauth2`: a client gets only what it declares and what it asked for

The authorization server granted more than a client declared or a request
asked for. It now enforces a fail-closed client policy, and **every client
must declare the grant types it uses and the scopes it may request** (step
3 below):

| | Before | After |
| --- | --- | --- |
| `Consent.Scope` adding scopes to a request without `scope` | granted — even scopes outside the client's `ScopeValues` | `invalid_scope`, nothing issued: a consent only narrows the request (RFC 6749 §3.3) |
| `Consent.Scope` made of spaces only | an empty grant | exactly what was requested, like an empty `Consent.Scope` |
| `client_credentials` by a public client (authenticated with `none`, its `client_id` alone) or an untyped one | issued, with the scope requested when `ScopeValues` was empty | `400 unauthorized_client` whatever the client declares: only confidential clients may use it (RFC 6749 §4.4) |
| `GrantTypes()` empty (`DefaultClient.GrantTypeValues` unset) | every grant allowed | no grant allowed: `400 unauthorized_client` at `/token` |
| a grant type the client does not declare, custom grants included | refused inside the shipped grants only — after a code was consumed — and never for a custom grant | `400 unauthorized_client` before the grant runs: a code or refresh token presented stays untouched |
| `/authorize` with `response_type=code` (`token`) by a client not declaring `authorization_code` (`implicit`) | code (implicit token) issued; a code was refused only at `/token` | redirected `unauthorized_client` in the flow's response mode, before the extension and the `ConsentFunc` run (RFC 6749 §4.1.2.1, §4.2.2.1; RFC 7591 §2.1) |
| `Profile20`: a public or untyped client without `code_challenge` | code issued and redeemed without PKCE | `/authorize`: redirected `invalid_request` (`code_challenge is required`, RFC 7636 §4.4.1); `/token`: a code issued without challenge is refused to it (`invalid_grant`, `PKCE required`) — RFC 9700 §2.1.1 |
| `Profile20` without `RotateRefreshTokens`: refresh of a public or untyped client | the refresh token stayed reusable until it expired | rotated like under the default profiles: a new refresh token with every refresh, reuse of the old one revokes the family (RFC 9700 §4.14.2); without a `RefreshTokens` generator the refresh fails with `server_error` |
| `Scopes()` empty (`DefaultClient.ScopeValues` unset) | any scope allowed | no scope allowed: a request carrying one is `invalid_scope`; one without scope gets the empty scope |
| refresh token at a code exchange or a password grant | issued whenever the grant has a `RefreshTokens` generator | issued only to a client declaring `refresh_token` (RFC 9700 §4.14.2) |
| a refusal caused by an empty declaration | — | `OnError` gets `oauth2.ErrNoGrantTypesDeclared` / `oauth2.ErrNoScopesDeclared` as cause |
| refresh whose access-token scope holds a scope the client no longer declares | issued: a refresh token kept its scope whatever the registration became | `400 invalid_scope`, nothing consumed; a narrowing inside the registration still refreshes |

To migrate:

1. A `ConsentFunc` that granted scopes to a request without `scope` — a
   default scope of its own — has the client request that scope instead:
   `Consent.Scope` can only narrow the request.
2. Register every machine-to-machine client as confidential
   (`TypeValue: oauth2.ClientConfidential`) with a high-entropy secret:
   `client_credentials` refuses public and untyped clients.
3. **Declare, for every client, the grant types it uses and the scopes it
   may request** — before upgrading: a client declaring none can no longer
   obtain anything. With `DefaultClient`:

   ```go
   &oauth2.DefaultClient{
       // ...
       GrantTypeValues: []string{oauth2.GrantTypeAuthorizationCode, oauth2.GrantTypeRefreshToken},
       ScopeValues:     []string{"openid", "profile", "offline_access", "api:read"},
   }
   ```

   Grant types are compared exactly with the RFC 7591 §2 values (the
   `oauth2.GrantType*` constants: `authorization_code`, `implicit`,
   `refresh_token`, `client_credentials`, `password`, or a custom grant's
   type); `implicit` gates the legacy `response_type=token`. A client that
   should receive refresh tokens declares `refresh_token`. An OpenID
   Connect client declares `openid` — plus `offline_access`, `profile`,
   `email`… as it requests them — and `authorization_code` (with
   `refresh_token` for offline access). Custom `Client` implementations: an
   empty `GrantTypes()` or `Scopes()` now means none.
4. Custom grants: the server checks the client's declaration before
   calling `Handle` (declare the custom grant type on the clients using
   it); a custom grant applies `Client.Scopes()` itself — exact match,
   empty meaning none — and can call `oauth2.ClientAllowsGrantType`.
5. After the upgrade, watch `ServerConfig.OnError` for
   `errors.Is(err, oauth2.ErrNoGrantTypesDeclared)` and
   `oauth2.ErrNoScopesDeclared`: they name the refusals of clients whose
   registration declares nothing.
6. Refresh tokens whose scope exceeds what their client now declares —
   issued when an empty `ScopeValues` meant any scope, or before the
   registration shrank — stop refreshing beyond it: the user authorizes
   again, or the client narrows its refresh requests to declared scopes.
7. Under `Profile20`, public and untyped clients send PKCE (S256) in their
   authorization requests, as the default profiles always required, and
   keep the refresh token each refresh returns (RFC 6749 §6): theirs now
   rotate. Give the `refresh_token` grant a `RefreshTokens` generator when
   such clients refresh.
8. No storage change: the policy applies per request, and instances may be
   upgraded one at a time.

### `oauth2`: repeated parameters and several client authentication methods are refused

RFC 6749 §3.1 and §3.2: "Request and response parameters MUST NOT be
included more than once". The server read the first value of a repeated
parameter, so a request carrying `redirect_uri` twice — the registered one,
then another — or a client and a request disagreeing on which value counts
were not refused. The parameters each endpoint reads are now single-valued:

| Request | Before | After |
| ------- | ------ | ----- |
| `/authorize` repeating `client_id`, `redirect_uri` or `response_mode` | the first value used | bare `400`, never redirected, whatever else the request repeats (the client, the target or the encoding of the answer are ambiguous); `OnError` gets `invalid_request` |
| `/authorize` repeating `response_type`, `scope`, `state`, `code_challenge`, `code_challenge_method` or `nonce` — a POST carrying one in the query and in the body included | the first value used | redirected `invalid_request` (`repeated <name>`); a repeated `state` is not echoed |
| `/token` repeating `grant_type`, `code`, `redirect_uri`, `code_verifier`, `refresh_token`, `scope`, `username`, `password`, `client_id` or `client_secret` | the first value used | `400 invalid_request` before the grant runs: a code presented stays redeemable |
| `/revoke`, `/introspect` repeating `token`, `token_type_hint`, `client_id` or `client_secret` | the first value used | `400 invalid_request` |
| a parameter repeated with an empty first occurrence (`scope=&scope=read`) | the empty first value used | the value: an empty occurrence is omitted (RFC 6749 §3.1) |
| `Authorization` header and a `client_secret` in the body | the header authenticated the client, the body secret was ignored | `400 invalid_request` (`more than one client authentication method`, RFC 6749 §2.3, §5.2), before any client is loaded |
| several `Authorization` header fields | the first one used | `400 invalid_request` (`more than one Authorization header`) |
| a body `client_id` naming another client than the one authenticated (Basic as A, `client_id=B`) | the authenticated client served | `400 invalid_request` (`client_id does not name the authenticated client`); the authenticated client's own `client_id` stays accepted (RFC 6749 §3.2.1) |
| an unrecognized parameter repeated | ignored | unchanged |
| `unsupported_grant_type` description | echoed the `grant_type` sent | a fixed text |

To migrate:

1. Clients send each parameter once, and authenticate with one method: an
   HTTP Basic header, or `client_id` and `client_secret` in the body — not
   both. A consent form posting back to
   `/authorize` must not repeat in its body a parameter the query already
   carries.
2. A `ConsentFunc` or an `Extension` reads the core's parameters from the
   `*oauth2.AuthorizeRequest`, never with `r.FormValue`: `r` is the request
   as received, where an empty occurrence can precede the value the server
   used. An extension refuses its own repeated parameters, as
   `oidc/provider` does.
3. A custom grant gets `GrantRequest.Form` with the core's parameters
   single-valued and its own as sent; a custom `ClientAuthenticator` reads a
   body parameter as its first non-empty occurrence.

### `oauth2`: `redirect_uri` at `/token` only when `/authorize` received one

RFC 6749 §4.1.3: `redirect_uri` is "REQUIRED, if the `redirect_uri`
parameter was included in the authorization request". A client with a single
registered redirect URI may omit it from its authorization request, but its
token request was then refused (`invalid_grant`, `redirect_uri mismatch`)
unless it sent the URI anyway. Codes now record whether the authorization
request named a redirect URI:

| Authorization request | Token request | Before | After |
| --------------------- | ------------- | ------ | ----- |
| named `redirect_uri` | the same URI | issued | unchanged |
| named `redirect_uri` | none, or another | `invalid_grant` | unchanged |
| omitted it (single registered URI) | none | `invalid_grant` | issued |
| omitted it | the registered URI | issued | unchanged |
| omitted it | another URI | `invalid_grant` | unchanged |

`oauth2.AuthorizationCode` gains `RedirectURIOmitted`; its zero value —
codes written before the upgrade included — keeps requiring `redirect_uri`.

To migrate:

1. **SQL.** `oauth2_auth_codes` gains a `redirect_uri_omitted` column, which
   `Migrate` does not add to an existing table. Until it exists, every code
   write and redemption fails with `server_error`. Apply, through your
   migration tool and before the new build serves traffic — the same
   statement on PostgreSQL, MySQL and SQLite:

   ```sql
   ALTER TABLE oauth2_auth_codes ADD COLUMN redirect_uri_omitted SMALLINT NOT NULL DEFAULT 0;
   ```

   Existing rows read `0`: their token requests keep requiring
   `redirect_uri`, as before.
2. **Redis and memory** need nothing: a code payload without the flag
   requires `redirect_uri`.
3. **Custom stores** persist and return `RedirectURIOmitted` — on the record
   of a `*oauth2.CodeReplayError` too — and pass `storetest.RunConformance`.
4. **Rollout.** Instances may be upgraded one at a time once the column
   exists: an earlier build writes the column default (required) and
   requires `redirect_uri` itself, which only refuses what it refused
   before.

### `oauth2`: an optional absolute lifetime for refresh-token families

`grant.Config.RefreshTTL` expires a refresh token its client leaves unused,
the inactivity expiry RFC 9700 §4.14.2 recommends; every rotation restarts
it, so a family refreshed often enough lived forever — including one a thief
keeps alive by rotating a token stolen from an idle client. Refresh tokens
now record when their family started (`oauth2.RefreshToken.FamilyIssuedAt`,
carried unchanged by every rotation), and the new
`grant.Config.RefreshFamilyTTL` bounds a family's lifetime from that start:

| | Before | After |
| --- | --- | --- |
| `RefreshFamilyTTL` zero (the default) | — | unchanged: families slide with `RefreshTTL` |
| `RefreshFamilyTTL` set | — | no refresh token expires past the family's start + `RefreshFamilyTTL`; a refresh after it is `invalid_grant` ("refresh token family expired"), nothing consumed; it applies at once to existing families |
| a refresh token written before the upgrade | — | its family counts from the token's own `IssuedAt` |

To migrate:

1. **SQL.** `oauth2_refresh_tokens` gains a `family_issued_at` column, which
   `Migrate` does not add to an existing table. Until it exists, every
   refresh-token write and lookup fails with `server_error`. Apply, through
   your migration tool and before the new build serves traffic — the same
   statement on PostgreSQL, MySQL and SQLite:

   ```sql
   ALTER TABLE oauth2_refresh_tokens ADD COLUMN family_issued_at BIGINT NOT NULL DEFAULT 0;
   ```

   Existing rows read `0`: no recorded start.
2. **Redis and memory** need nothing: a payload without the field has no
   recorded start.
3. **Custom stores** persist and return `FamilyIssuedAt` on every refresh
   token — a consumed one included — the zero time as the zero time, and
   pass `storetest.RunConformance`.
4. To bound sessions, set `grant.Config.RefreshFamilyTTL` on the grants —
   the `refresh_token` grant and the grants issuing refresh tokens — to the
   longest session you accept: users then sign in again at least that
   often. Set it once every instance runs this release: an instance still
   on the previous one writes refresh tokens without a family start, so
   each rotation it serves restarts the bound.

### `saml/sp`: a server-held key protects the login transactions; one verification per login; stricter location and correlation checks (security audit 2026-10-12)

The SAML Service Provider stored its login transactions without integrity
protection: whoever could write to the transaction store — a shared Redis,
a database user — could rebind a captured response to another browser or
request, or drop the `ForceAuthn` and `RequestedAuthnContext` requirements of
a login. A transaction also allowed any number of signature verifications,
a response was checked against the path of the URL it was received at only,
and several parser and correlation details deviated from SAML 2.0 Core. The
fixes change the configuration, the stored records and some refusals:

| | Before | After |
| --- | --- | --- |
| `Config.TransactionKeys` | — | REQUIRED: 1 to 4 keys of at least 32 bytes; `New` fails with `ErrInvalidConfig` otherwise |
| `TransactionRecord.Integrity` | — | HMAC-SHA256 under `TransactionKeys[0]` over the ID, `BindingHash`, `Payload` and `ExpiresAt`; required by `Validate`; verified under any of the keys, in constant time, before any stored field is used |
| a record altered in the store | used as stored | `ErrTransactionIntegrity`, nothing consumed |
| logins in progress at the upgrade | — | fail once with `ErrTransactionIntegrity` (the user signs in again) |
| SQL store | `samlsp_transactions` without `integrity` | column `integrity VARCHAR(64) NOT NULL`; `Migrate` does not alter an existing table |
| Redis store | hash fields `b`, `p`, `e` (+ `c`) | + `i` (integrity) and `n` (nonce of the saving call); a second save of an existing transaction, even identical, is `ErrTransactionExists` |
| custom stores | — | persist and return `Integrity` unchanged; `storetest.RunConformance` checks it, an identical second save, and retention over time (a run takes about 1.5 s more) |
| `TransactionRecord.Payload` | NUL-free UTF-8 | NUL-free 7-bit ASCII (the SP escapes every other character): no store needs `utf8mb4` or a strict `sql_mode` for it |
| a response refused after the browser binding, transaction, status and `InResponseTo` checks (signature, issuer, audience, times…) | transaction kept, any number of retries | transaction consumed before the verification: one verification per login, the user restarts the login (`ErrTransactionConsumed` for any later POST) |
| the ACS request | path checked | escaped path, host (`r.Host`) and no query string checked: `ErrDestinationMismatch` |
| a Success `Response` without `InResponseTo` | accepted | `ErrUnsolicitedResponse` (Core §3.2.2) |
| a Success status code followed by white space | refused after signature work (`ErrResponseStatus`) | `ErrMalformedResponse`, before any signature work |
| `xml:` attributes other than `xml:lang`, `xml:space`, `xml:base`, `xml:id` | accepted | `ErrMalformedResponse` |
| a `KeyInfo` without `X509Certificate` | `ErrInvalidSignature` | treated as absent (cut from the verified bytes); still `ErrInvalidSignature` on an Assertion covered by a signed Response |
| replay cache key | digest of (issuer, assertion ID) | digest of (connection, issuer, assertion ID) |
| an `EntitiesDescriptor` (aggregate) without a pinned entity ID | imported when it lists one entity | `ErrInvalidMetadata` |
| `Connection.ACSURL` | any host | an ASCII host (the punycode form of an internationalized name) |
| `Connection.ResponseOrigins` | — | optional: the IdP origins allowed to post to the ACS (`Origin`, else `Referer`); `ErrOriginMismatch` otherwise |
| `fmt` / `log/slog` of a `Config` or a `*ServiceProvider` | every field, signing key included | settings only, with every `fmt` verb; keys redacted |

To migrate:

1. Generate a transaction key: 32 bytes or more from a cryptographic source
   (`openssl rand -hex 32`). Keep it in your secret store, and use a key
   distinct from the OpenID Connect client's transaction keys and from the
   session keys.
2. Set `Config.TransactionKeys: [][]byte{key}` on every instance — the same
   keys everywhere (`examples/saml-sp` reads `SAMLSP_TRANSACTION_KEYS`, hex
   keys separated by commas).
3. With `saml/sp/store/sql`, add the column before deploying:
   `ALTER TABLE samlsp_transactions ADD COLUMN integrity VARCHAR(64) NOT NULL DEFAULT ''`
   (PostgreSQL, MySQL and SQLite), or drop the table and run `Migrate`: it
   only holds logins in progress. With `saml/sp/store/redis`, nothing to do.
   A custom `TransactionStore` must persist `TransactionRecord.Integrity`
   and return it unchanged: run `storetest.RunConformance` against it.
4. Deploy knowing that the logins in progress fail once
   (`ErrTransactionIntegrity`); the users start over.
5. Behind a reverse proxy, forward the original `Host` (nginx:
   `proxy_set_header Host $host;`), or pass `CompleteLogin` a copy of the
   request (`r.Clone`) whose `Host` comes from your trusted proxy's
   header; never trust a forwarding header a client can set.
6. Pass `MetadataOptions.EntityID` (or `FetchOptions.EntityID`) to import
   metadata served as an `EntitiesDescriptor`, even of a single entity.
7. Optionally set `Connection.ResponseOrigins` to the origin of the IdP
   page that posts the responses, when that page lets browsers send it.
   Keycloak's default realm does not: its POST page sends
   `Referrer-Policy: no-referrer`, so browsers post `Origin: null`. Leave
   the option unset there, or first set the realm's Referrer-Policy header
   (Realm settings → Security defenses → Headers) to
   `strict-origin-when-cross-origin`.
8. To rotate a transaction key later without failing a login: add the new
   key last on every instance; once all of them run with it, move it first;
   remove the old key once `TransactionTTL` (10 minutes by default) has
   elapsed.

### core: failures return the anonymous authentication; contract violations fail closed

After a failed authentication, `Engine.Process` stored the extracted
`Authentication` — a cleartext password, a bearer token — in the request
context and returned it, and `Manager.Authenticate` returned it too. A
component breaking its contract made the request path panic: an
authenticator returning `(nil, nil)` or a typed nil (`var out *T; return
out, nil`), a nil `Attribute`, a nil `Authentication` passed to `Decide`. And an authenticator bailing out at
runtime with `ErrUnsupportedCredential` — the documented way to do so — had
its error joined with the other authenticators' refusals, so a wrong password
could be answered as an unsupported credential.

| Situation | Before | After |
| --- | --- | --- |
| `Engine.Process` / `Manager.Authenticate` fail | return (and store) the extracted value | return (and store) `security.Anonymous()` |
| An authenticator returns `(nil, nil)` or a typed nil | panic | refusal; the next authenticator is tried |
| An authenticator returns an unauthenticated value and no error | success | refusal (contract violation) |
| A custom `Manager` returns no authenticated value (nil, typed nil) and no error | panic / success | `Process` fails |
| An extractor returns a typed nil and no error | handed to the authenticators (panic) | no credential: the next extractor runs |
| An authenticator returns an error wrapping `ErrUnsupportedCredential` only | joined into `ErrAuthenticatorRefused` | abstention; `ErrUnsupportedCredential` when every supporting authenticator bails out |
| … wrapping `ErrUnsupportedCredential` and a verdict (`ErrInvalidCredentials`, `ErrUnavailable`, `ErrInvalidRequest`, …) | joined | that verdict (`security.ErrorClass` order) |
| `Decide` with a nil or typed nil `Attribute` | panic | `ErrAccessDenied` |
| `Decide` with a nil or typed nil `Authentication` | panic | evaluated as `security.Anonymous()` |
| `FromContext` after `WithAuthentication(ctx, typedNil)` | the typed nil | `security.Anonymous()`, `false` |
| A voter returns an undefined `Decision` | ignored (abstention) | counted as `DecisionDeny` |
| `NewEngine(nil, …)`, a nil extractor, authenticator or voter | panic on the first request | panic at construction |

To migrate:

1. Do not read the presented credentials from the value `Engine.Process`
   returns on failure: it is `security.Anonymous()`. Per-username throttling
   or lockout belongs in an `Authenticator` wrapper, which sees the
   credentials before they are checked.
2. Make every `Authenticator` (and `bearer.TokenVerifier`) return an
   authenticated value on success, and an error wrapping a security sentinel
   otherwise.
3. Pass non-nil managers, extractors, authenticators, voters and attributes.
4. Make the `Authorities` method of your own `Authentication` types return a
   copy (`slices.Clone`): `basic`, `bearer` and `session` now do, so a caller
   can no longer rewrite the authorities of an authenticated value.

### `voter`: voters compare attribute values; dedicated authentication-state attributes

The attributes passed to `AccessDecisionManager.Decide` (and to
`httpsec.Authorize`, `grpcsec.UnaryAuthorize`, …) only selected *which*
voters ran: a role voter checked the role it was built with whatever role
the route asked for, and `voter.Authenticated()` / `voter.Anonymous()` voted
on every attribute. A decision manager shared by several routes therefore
granted an ADMIN route to a USER, `Authenticated()` next to a role voter
granted any route to any logged-in principal, `HasAnyRole("ADMIN",
"MANAGER")` granted a MANAGER on `Role("ADMIN")`, and `voter.Not()` turned
the refusal of an anonymous caller into a grant. The voters now follow
Spring Security's semantics: the attributes a route lists are its policy,
and each voter votes only on the attributes whose family **and** value it
supports.

| Policy | Before | After |
| --- | --- | --- |
| ADM `{HasRole("USER"), HasRole("ADMIN")}`, USER on `[Role("ADMIN")]` | granted | denied |
| ADM `{HasRole("USER")}` on `[Role("ADMIN")]` | role USER checked | denied (no voter supports `Role("ADMIN")`) |
| `HasAnyRole("ADMIN", "MANAGER")`, MANAGER on `[Role("ADMIN")]` | granted | denied; granted on `[Role("ADMIN"), Role("MANAGER")]` |
| ADM `{Authenticated(), HasRole("ADMIN")}`, USER on `[Role("ADMIN")]` | granted | denied |
| ADM `{Authenticated()}` on `[Role("X")]` | any logged-in principal | denied — list `security.IsAuthenticated` |
| ADM `{Anonymous()}` on `[Role("X")]` | any anonymous caller | denied — list `security.IsAnonymous` |
| `Not(HasRole("BANNED"))`, anonymous on `[Role("BANNED")]` | granted | denied |
| `And(HasRole("USER"), Not(HasRole("BANNED")))` on `[Role("USER")]` | banned users granted | denied for everyone — list `[Role("USER"), Role("BANNED")]` |
| Unanimous / consensus with an attribute no voter supports | ignored | denied |
| Unanimous with `WithAbstainFallback(DecisionGrant)`, no attribute or no voter | granted, anonymous callers included | denied |
| `voter.FullyAuthenticated()` | same as `Authenticated()` | removed |

To migrate:

1. Make every route's attributes name exactly what its voters check, and
   give the decision manager a voter for every attribute: `Authorize(adm,
   security.Role("ADMIN"))` with `voter.HasRole("ADMIN")` in `adm`. An
   attribute that no voter supports now denies the request, and so does a
   route without attributes, whatever the strategy, tie-break or
   `WithAbstainFallback` (which only decides for custom voters that support
   an attribute and abstain).
2. Require a logged-in or a logged-out caller with an attribute:
   `voter.Authenticated()` with `security.IsAuthenticated`,
   `voter.Anonymous()` with `security.IsAnonymous`.
   `voter.FullyAuthenticated()` is gone: use `voter.Authenticated()`.
3. With `HasAnyRole` / `HasAnyScope` / `HasAnyAuthority`, list every name the
   route accepts among its attributes.
4. With `voter.And`, list one attribute per inner requirement: every inner
   voter must grant. `And(HasRole("USER"), Not(HasRole("BANNED")))` needs
   `[Role("USER"), Role("BANNED")]`. A `Role("X")` attribute is decided by
   every voter supporting it, negated ones included: a decision manager
   holding `Not(HasRole("X"))` grants `[Role("X")]` routes to principals
   *without* X. Keep such a policy in its own decision manager.
5. Do not rely on `voter.Not` to admit anonymous callers:
   `Not(Authenticated())` never grants them — use `voter.Anonymous()` with
   `security.IsAnonymous`.
6. Custom voters: `Supports` must check the attribute's value, not only its
   type, and `Vote` must consider only the attributes it supports (the
   decision manager now passes it only those) and abstain without them.

### `voter`: roles and scopes live in their own authority namespaces

`voter.HasRole("admin")` accepted the authority `admin` as well as
`ROLE_admin`, and `voter.HasScope("admin")` accepted `admin`, `scope:admin`
and any `scope:…` authority holding `admin` among space-separated words: one
bare `admin` authority — a scope a client obtained, a fine-grained
permission — satisfied the role, the scope and the authority checks at once,
and one authority string could carry many scopes. `HasRole("")` matched
`ROLE_`.

| Authority held | Check | Before | After |
| --- | --- | --- | --- |
| `ROLE_admin` | `HasRole("admin")` | granted | granted |
| `admin` | `HasRole("admin")` | granted | denied |
| `scope:admin` | `HasScope("admin")` | granted | granted |
| `admin` | `HasScope("admin")` | granted | denied |
| `scope:read billing:admin` | `HasScope("billing:admin")` | granted | denied |
| `admin` | `HasAuthority("admin")` | granted | granted (unchanged) |
| — | `HasRole("")`, `HasRole("ROLE_X")`, `HasScope("a b")`, `HasScope("scope:x")`, `HasAnyRole()` | constructed | panic at construction |

To migrate:

1. Emit roles as `security.RolePrefix + name` (`ROLE_ADMIN`) from your
   `basic.WithAuthorityResolver` and `session.PrincipalLoader`
   implementations — `examples/basic-http` shows it.
2. Emit one `security.ScopePrefix + scope` authority per scope
   (`scope:read:mail`): `jwtsec.DefaultAuthorityResolver` already does; split
   a space-separated `scope` claim before prefixing it.
3. Keep `HasAuthority` for verbatim, unprefixed authorities.
4. Pass the bare name to `HasRole`/`security.Role` (`"ADMIN"`, not
   `"ROLE_ADMIN"`), and valid RFC 6749 §3.3 scope-tokens to
   `HasScope`/`security.Scope`.

### `http`, `session`: credentials from header fields only, the session from its cookie only

`httpsec.Carrier.Get` and `Values` fell back to a cookie, then to the query
string, named like the key. The Basic and Bearer extractors read
`Get("Authorization")`, so credentials were accepted from `?Authorization=…`
and from a cookie named `Authorization`; and `session.Manager` read
`Get(cookieName)`, so a session was accepted from `?session=…` and from a
`Session` request header, which even took precedence over the real cookie.
Credentials in URLs leak through access logs, `Referer` and history (RFC
6750 §5.3), and a link or a cross-site form carrying an attacker's session
value logged the victim into the attacker's account.

| Request | Before | After |
| --- | --- | --- |
| `Authorization` header (Basic, Bearer) | authenticated | unchanged |
| `?Authorization=Basic …` / `?Authorization=Bearer …` | authenticated | no credential (401 without anonymous fallback) |
| Cookie `Authorization="Bearer …"` | authenticated | no credential |
| Session cookie | session | unchanged |
| `?session=<value>` or `Session: <value>` header, no cookie | session | no session |
| Session cookie and a `Session` header | the header's session | the cookie's session |
| `session.Manager` used with a carrier without `CookiesNamed` | the carrier's `Get(cookieName)` | no session (`ErrNoSession`) |

To migrate:

1. Send credentials in the `Authorization` header and the session in its
   cookie; nothing else is read.
2. A custom `security.Carrier` used with `session.Manager` must implement
   `session.CookieReader` (`CookiesNamed(name string) []*http.Cookie`, as
   `httpsec.Carrier` does); its `Get`/`Values` must read header fields only.

### `http`: challenges and status codes follow RFC 6750, RFC 7617 and RFC 9110

The default HTTP error mapping answered a Basic-only server with a bare
`Bearer` challenge, sent no realm (RFC 7617 §2 requires one; RFC 6750 §3
requires an auth-param after `Bearer`), rendered the realm with Go escapes,
sent `invalid_token` only for expired or unknown tokens (RFC 9068 §4: for
every failed check), never sent `insufficient_scope`, answered `400` when a
wrong password was joined with another authenticator's bail-out, `403` to an
anonymous caller refused by `Authorize` (with a hard-coded bare `Bearer`),
and `401` to an infrastructure failure. The mapping now comes from
`security.ErrorClass`:

| Situation | Before | After |
| --- | --- | --- |
| No credentials | `401 Bearer` | `401 Bearer realm="api"` |
| No credentials, `WithChallengeScheme("Basic")` | `401 Basic` | `401 Basic realm="api", charset="UTF-8"` |
| Bad bearer token (signature, audience, malformed…) | `401 Bearer` | `401 Bearer realm="api", error="invalid_token", …` |
| Bad credentials, no bearer token sent | `401 Bearer` | `401 Bearer realm="api"` (no RFC 6750 code) |
| Unsupported credential (no authenticator supports it) | `400`, no challenge | `401` with challenge, no error code |
| Wrong password next to an authenticator bailing out | `400`, no challenge | `401` with challenge |
| Authenticated principal refused by `Authorize` | `403 Bearer` | `403 S realm=R` (`error="insufficient_scope"` for a bearer request) |
| Unauthenticated principal refused by `Authorize` | `403 Bearer` | `401` with the `Middleware`'s challenge |
| Repeated `Authorization` field | first value used | `400` with the challenge for a Bearer resource (`invalid_request` for a bearer request) |
| `ErrUnavailable` (store, key set down) | `401` | `503` (with a bare challenge for a Bearer resource) |
| Error wrapping no sentinel, `ErrNoExtractor`, a custom `Engine` returning no context or a typed nil | `401` / panic | `500` (with a bare challenge for a Bearer resource) |
| Realm with a control or non-ASCII character | Go-escaped | `Middleware` / `DefaultErrorMapper` panic |
| `Middleware(nil)` | panic on the first request | panic at construction |
| `Authorize(adm, …, nil)` (a nil or typed nil attribute) | panic on every request | panic at construction |
| Reusing the attribute slice passed to `Authorize` | rewrote the route's policy | no effect (copied) |

To migrate:

1. Set `WithChallengeScheme("Basic")` on a Basic-only middleware, and
   `WithRealm` if `api` does not suit; use printable ASCII in the realm.
2. Make clients treat `401` as "send (other) credentials", including after an
   `Authorize` refusal of an anonymous request, and `503` as "retry later".
3. Authenticators: wrap `security.ErrUnavailable` for a dependency that is
   temporarily down, a credential sentinel for a refusal; an error wrapping
   no sentinel is now an internal error (500).
4. Custom `ErrorMapper`s: classify with `security.ErrorClass` and handle the
   new classes (`invalid_request`, `unavailable`,
   `authentication_required`).
5. Dashboards: the `httpsec.Middleware` span records `http.request.method`
   (instead of `http.method`) and `http.route` only as a route template.

### `grpc`: status codes and messages, staged headers, server options

The gRPC error mapping told the client why authentication failed
(`token expired`, `token not found`), answered an infrastructure failure
`Unauthenticated`, an unsupported credential `InvalidArgument` and an
anonymous caller refused by `UnaryAuthorize` `PermissionDenied`; the
metadata an extractor staged on the carrier was never sent; and the
documented wiring (`grpc.ChainUnaryInterceptor` only) left streaming RPCs
unauthenticated.

| Situation | Before | After |
| --- | --- | --- |
| Credential failure | `Unauthenticated` + reason (`token expired`…) | `Unauthenticated`, `unauthenticated` |
| Unsupported credential | `InvalidArgument` | `Unauthenticated` |
| Anonymous caller refused by `UnaryAuthorize` / `StreamAuthorize` | `PermissionDenied` | `Unauthenticated` |
| Repeated `authorization` metadata | first value used | `InvalidArgument` |
| `ErrUnavailable` | `Unauthenticated` | `Unavailable` (retryable) |
| Error wrapping no sentinel, `ErrNoExtractor` | `Unauthenticated` | `Internal` |
| Metadata staged on the `Carrier` | dropped | sent as the response header |
| `UnaryAuthorize` without `WithErrorMapper` | `DefaultErrorMapper()` | the authentication interceptor's mapper |
| A nil engine (`UnaryServerInterceptor(nil)`, `ServerOptions(nil)`, …) | server crash on the first RPC | panic at construction |
| A custom `Engine` returning no context or a typed nil | server crash | `Internal` |
| A nil or typed nil attribute given to `UnaryAuthorize` / `StreamAuthorize` / `AuthorizeServerOptions` | panic on every RPC: the server crashes | panic at construction |
| Reusing the attribute slice passed to them | rewrote the RPC's policy | no effect (copied) |

To migrate:

1. Install the stream interceptors next to the unary ones — simplest:
   `grpc.NewServer(slices.Concat(grpcsec.ServerOptions(engine),
   grpcsec.AuthorizeServerOptions(adm, attrs))...)`.
2. Branch on the status code, never on the message.
3. Authenticators: wrap `security.ErrUnavailable` only for a transient
   dependency failure (clients retry `Unavailable`), a credential sentinel
   for a refusal.

### `connectrpc`: challenges on 401, generic codes and messages

A ConnectRPC unary call refused with `Unauthenticated` is an HTTP 401, which
MUST carry a `WWW-Authenticate` challenge (RFC 9110 §11.6.1); none was sent.
The Connect error messages also told the client why authentication failed,
and infrastructure failures read as `Unauthenticated`. The default mapper now
takes the challenge configuration and answers like the gRPC one:

| Situation | Before | After |
| --- | --- | --- |
| `DefaultErrorMapper()` | no argument | `DefaultErrorMapper(scheme, realm string)` (`""` → `Bearer`, `DefaultRealm`) |
| Unauthenticated / PermissionDenied | no `WWW-Authenticate` | challenge in the error metadata (HTTP headers for unary calls) |
| Credential failure | reason in the message | `unauthenticated` |
| Unsupported credential | `InvalidArgument` | `Unauthenticated` |
| Anonymous caller refused by the authorization interceptor | `PermissionDenied` | `Unauthenticated` |
| Repeated `Authorization` field | first value used | `InvalidArgument` |
| `ErrUnavailable` / error wrapping no sentinel | `Unauthenticated` | `Unavailable` / `Internal` |
| `InvalidArgument`, `Unavailable`, `Internal` of a Bearer resource | no `WWW-Authenticate` | `Bearer realm=R` (RFC 6750 §3; `invalid_request` for a bearer request) |
| Headers staged on the `Carrier`, refused call | dropped | in the error metadata |
| `NewAuthenticationInterceptor(nil)` | panic on the first RPC | panic at construction |
| A custom `Engine` returning no context or a typed nil | panic | `Internal` |
| A nil or typed nil attribute given to `NewAuthorizationInterceptor` | panic on every RPC | panic at construction; the attributes are copied |

To migrate:

1. Replace `connectrpcsec.DefaultErrorMapper()` by
   `connectrpcsec.DefaultErrorMapper("Bearer", connectrpcsec.DefaultRealm)`
   (or your scheme and realm), or configure the interceptors with
   `connectrpcsec.WithChallengeScheme` / `connectrpcsec.WithRealm`.
2. Branch on the code, never on the message.

### `jwt`: claims are decoded case-sensitively and strictly

The verifier decoded claims with `encoding/json`, which matches member names
case-insensitively and keeps the last duplicate: a signed `"Sub"`, `"SCOPE"`,
`"EXP"`, `"AUD"` or `"ſub"` overrode the registered claim. RFC 7519 §4 requires
unique claim names, §7.3 and §10.1.1 case-sensitive ones. Claims — into
`StandardClaims` and into your `claimsOut` — are now decoded by go-jose's
case-sensitive decoder, after a strict validation of the payload.

| Payload or claims type | Before | After |
| --- | --- | --- |
| `"sub"` next to `"Sub"`, `"SUB"` or `"ſub"`, at any depth | the last case-insensitive match won | `ErrMalformedToken` |
| `"sub"` twice | the last one won | `ErrMalformedToken` |
| `"SUB"` without `"sub"` | `Subject` = its value | `Subject` empty: `"SUB"` is a private claim |
| `claimsOut` field `Email string` without tag, payload `"email"` | filled | not filled |
| `claimsOut` field of type `encoding/json.Number` | filled | `ErrMalformedToken` |
| `"nbf": null`, `"exp": "123"`, `"aud": [1]`, `"sub": null` | ignored or coerced | `ErrMalformedToken` |
| invalid UTF-8, an unpaired surrogate escape, a `null` or array payload | accepted | `ErrMalformedToken` |

To migrate:

1. Give every `claimsOut` field the exact claim name as its `json` tag.
2. Replace `encoding/json.Number` fields with `float64`, `int64` or
   `json.RawMessage`; do not read `claimsOut` after `Verify` failed.
3. Make issuers emit claim names that differ by more than case.

### `jwt`: tokens are size-bounded and parsed strictly

go-jose decoded a token's header — about 100 times its size in allocations —
before any check, whatever the token's length.

| | Before | After |
| --- | --- | --- |
| token length | unbounded | at most `DefaultMaxTokenSize` (16 KiB); `WithMaxTokenSize(n)` on a `Verifier`; `VerifySignature` uses the default |
| encoding | lenient base64url (non-zero pad bits, CR/LF ignored) | canonical unpadded base64url only |
| header | go-jose's rules | strict JSON (no duplicate or case-variant names, UTF-8); `crit` and `b64` refused, even `null` |
| algorithm outside the allow-list | `ErrMalformedToken` | `ErrAlgorithmNotAllowed` (`AsAlgorithmName` gives it, clipped) |
| token values in errors and spans | unbounded | clipped to 128 bytes |

To migrate:

1. If your tokens exceed 16 KiB, raise the bound with
   `jwtsec.WithMaxTokenSize`.
2. Match `jwtsec.ErrAlgorithmNotAllowed` where you matched
   `ErrMalformedToken` for refused algorithms.
3. Cap request headers at the transport (`http.Server.MaxHeaderBytes`,
   `grpc.MaxHeaderListSize`).

### `jwt`: every verification key is bound to one algorithm and validated

RFC 8725 §3.1: "each key MUST be used with exactly one algorithm, and this
MUST be checked". `VerifySignature` checked it; the `Verifier` did not, nor did
it check the key (RFC 7518 §3.3: RSA keys of 2048 bits or more).

| Static or custom key | Before | After |
| --- | --- | --- |
| `Algorithm: RS256`, token RS384 or PS256 | verified | `ErrInvalidSignature` |
| no `Algorithm` | verified the token's algorithm | verifies nothing |
| RSA under 2048 bits, a private key, a `jose.JSONWebKey` in `PublicKey.Key` (an HMAC secret's included) | verified | `ErrInvalidSignature` wrapping `ErrInvalidKey` |
| two keys with the token's `kid` | the first | none |
| token without `kid`, several keys | the key without `KeyID` | none |

To migrate:

1. Set `Algorithm` on every `PublicKey` you build.
2. Replace RSA keys under 2048 bits; pass public keys (`*rsa.PublicKey`,
   `*ecdsa.PublicKey`, `ed25519.PublicKey`) or, for HMAC, the `[]byte`
   secret — not private keys or JWKs.
3. Give every key its own `kid`.

### `jwt`: `exp`, NumericDates and the clock skew are enforced strictly

A year-1 `exp` — what a zero `time.Time` marshalled to, and what the RFC 9068
signer emitted for a zero `ExpiresAt` — disabled the expiry check.

| | Before | After |
| --- | --- | --- |
| `now == exp + skew` | accepted | `ErrTokenExpired` (RFC 7519 §4.1.4) |
| a NumericDate before 1970 or after 9999-12-31T23:59:59Z, year 1 included | expiry disabled or wrapped around | `ErrMalformedToken` |
| signing such a date, a zero `time.Time` included | signed | `Sign` fails with `ErrUnsignableClaims` |
| `WithClockSkew(d)` with `d < 0` or `d > 5 min` | clamped to 0 / accepted | panics (`MaxClockSkew`) |

To migrate:

1. Leave an absent date `nil` (`*NumericDate`) rather than zero.
2. Keep the skew within `jwtsec.MaxClockSkew`.

### `jwt`: signers validate their key and return errors; RFC 9068 claims are required

`NewSigner` signed with RSA-1024, a public key or a short HMAC secret, and the
RFC 9068 signer emitted empty `aud`, `iss`, `sub` or `client_id` (for instance
with `StaticIssuer(iss, "")`).

| | Before | After |
| --- | --- | --- |
| `NewSigner(key, opts...) Signer` | panicked on a missing `Algorithm` or `Key`, accepted any other key | `NewSigner(key, opts...) (Signer, error)`: `ErrInvalidKey` for a key unfit for its algorithm; KMS / HSM keys (`jose.OpaqueSigner`) checked through their public half; `jose.JSONWebKey` unwrapped |
| `NewOAuth2AccessTokenSigner(key) *OAuth2AccessTokenSigner` | same | `(*OAuth2AccessTokenSigner, error)` |
| `SignAccessToken` with an empty `Issuer`, `Subject`, `Audience` or `ClientID`, a zero `IssuedAt` or `ExpiresAt`, `ExpiresAt` not after `IssuedAt` | signed | `ErrUnsignableClaims` (no security sentinel), nothing signed — the OAuth2 grants answer `server_error` |

To migrate:

1. Handle the error of `NewSigner` and `NewOAuth2AccessTokenSigner`.
2. Give HMAC secrets at least the hash size (32, 48, 64 bytes).
3. With JWT access tokens, make the `IssuerResolver` return a non-empty
   audience for every realm.

### `jwt`: `NewRemoteJWKS` fetches through `outbound` with a bounded refresh

The remote provider fetched outside the `outbound` SSRF guard, held a lock
across the fetch, re-fetched on every call while the upstream failed, served a
stale set forever, never refreshed on an unknown `kid`, and trusted every key.

| | Before | After |
| --- | --- | --- |
| signature | `NewRemoteJWKS(url, opts...) JWKSProvider` | `NewRemoteJWKS(url, opts...) (JWKSProvider, error)`: the URL must be absolute https with a host and no userinfo (http only with `AllowHTTP` or `WithHTTPClient`) |
| client | `http.Client{Timeout: 10s}`, default transport | `outbound.NewClient(outbound.Policy{})`, or `WithOutboundPolicy(p)`; `WithHTTPClient` is an explicit opt-out, still bounded (10 s, 1 MiB) |
| loopback, private, link-local destination; plain http | fetched | refused unless the policy allows it |
| redirects | followed, to any origin | none by default; those `MaxRedirects` (or the `WithHTTPClient` client) allows stay on the JWK Set URL's origin — another origin fails with `outbound.ErrRedirectNotAllowed`; a response over http for an https URL is never trusted |
| environment proxies | used | ignored |
| refresh | under a lock; on every call while failing; stale set used forever; none on an unknown `kid` | one fetch at a time in the background after the TTL; at most every 10 s; back-off up to 5 min; set unused after 24 h; one refresh on an unknown `kid` |
| keys | all kept; one unsupported key failed the set | validated one by one, unusable ones ignored; RSA without `alg`: RS256 if allowed, else the verifier's only RSA algorithm |
| `WithCacheTTL(0)` | fetched on every call | panics: the TTL is in (0, 24 h] |
| an outage seen by `Verify` | a plain error (401) | `ErrKeySetUnavailable`, wrapping `security.ErrUnavailable` and no credential sentinel: 503 / Unavailable at the transports |

To migrate:

1. Handle the error of `NewRemoteJWKS`.
2. For a JWKS host on a private network, pass
   `jwtsec.WithOutboundPolicy(outbound.Policy{AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}})`
   (and `RootCAs` for a private CA); in tests against `httptest`, use
   `outbound.Policy{AllowHTTP: true, AllowedPrefixes: outbound.LoopbackPrefixes()}`.
3. In a custom error mapper, answer `security.ErrUnavailable`
   (`security.ErrorClass`: `unavailable`) with 503: a key set outage wraps it.
4. If your JWK Set URL redirects to another origin (a CDN, another host),
   configure the final URL.

### `jwt`: `BearerVerifier` requires issuer, audience and `at+jwt`

RFC 9068 §4 requires a resource server to check `typ` (`at+jwt`), `iss`, `aud`
and `exp`. `BearerVerifier` accepted any verifier — the bundled examples
checked no `typ` — so an ID Token or another API's access token was accepted.

| | Before | After |
| --- | --- | --- |
| `BearerVerifier(v, resolver)` | any `Verifier` | panics unless `v` comes from `NewVerifier` with `WithIssuer`, `WithAudience` and `WithType(TypeAccessToken)`, without `WithOptionalExpiry` |
| an authorization server typing its access tokens `JWT` | accepted with any verifier | `NewVerifier(…, WithType("JWT"))` and `BearerVerifier(v, nil, WithAccessTokenType("JWT"))` |
| an untyped access token | accepted | refused (`ErrInvalidType`) |
| a token without `sub` | an authentication with an empty name | `ErrInvalidClaims` |
| `WithAudience("")` or `WithAudience("api", "")` | accepted, matched `"aud": ""` | panics |

To migrate:

1. Build the verifier with `jwtsec.WithIssuer(iss)`,
   `jwtsec.WithAudience(aud)` and `jwtsec.WithType(jwtsec.TypeAccessToken)`;
   sign access tokens with `NewOAuth2AccessTokenSigner`.
2. For an authorization server typing access tokens `JWT`, add
   `WithType("JWT")` to the verifier and `WithAccessTokenType("JWT")` to
   `BearerVerifier` — only if your audience is never the `client_id` of one of
   its clients.
3. For untyped access tokens, wrap your own verifier in a
   `bearer.VerifierFunc`.

### `jwt`: `PublicKey` encodes only public asymmetric keys

`PublicKey.MarshalJSON` redacted only a `[]byte` HMAC secret: an HMAC secret
held as a `jose.JSONWebKey`, and a private key placed in a `PublicKey`, were
written in full. Every key that is not an `*rsa.PublicKey`,
`*ecdsa.PublicKey` or `ed25519.PublicKey` is now redacted
(`"Key": "<type> REDACTED"`) in JSON, `fmt` and `slog`. Nothing to migrate.

### `oidc/provider`: claim names that differ only by case are never released

Claim names are case-sensitive (OIDC Core §5.1, RFC 7519 §4), and the
provider compared them byte for byte: an end-user whose `ClaimsSource`
attributes she names herself (custom profile attributes, attributes passed
through from an upstream directory) could add to her own authorization
request a `claims` parameter naming one `"SUB"` or `"ſub"` (U+017F). It was
released next to the genuine `sub`, and relying parties matching names
case-insensitively — Go's `encoding/json`, so go-oidc and most Go relying
parties, last member winning — read the victim's subject from her ID Token
and UserInfo response (account takeover). The same held for any claim
(`"Roles"` read as `roles`), and source names with invalid UTF-8 were written
as one duplicated member.

The provider now compares claim names under a key that ignores case (simple
and full case mappings: `ſ`, `K`, `İ`, `ı`, `ß`, `ﬁ`…) and the `_` and `-`
delimiters, and drops — dropping is never an error (Core §5.3.2, §5.5):

| Released claim | Before | After |
| --- | --- | --- |
| `SUB`, `ſub`, `s_ub`, `Iss`, `iß`, `authtime`, `SUB#fr`… (case variants of protocol claims) | released next to the protocol claims | never asked of the source, never shown to the `Interaction`, never released |
| `Email`, `e_mail`, `EMAIL#fr`, `Roles`, `roleſ`… (other spellings of standard claims, of `roles`/`groups`/`entitlements`, of `ClaimsSupported`) | released | dropped; `email`, `email#fr`, `roles` are released |
| `team` and `teaM`, `name#fr` and `name#FR` (case variants of one another) | both released | both dropped |
| a source name with invalid UTF-8, a control character or over 255 bytes (a tagged variant) | released, invalid UTF-8 as U+FFFD | dropped |
| a value with case-variant, invalid or control-character member names at any depth, an unpaired surrogate escape, a number beyond float64, or nested over 31 levels | released | dropped |
| a `claims` request for a name never released | shown in `Request.Claims`, recorded with the grant | left out of both (`Subjects`, `EssentialACR` unchanged) |
| `Config.ClaimsSupported` with `azp`, `jti`, `sid`, `nbf`, `cnf`, `scope`, `client_id`, `typ`, `c_hash`, `s_hash`, `_claim_names`, `_claim_sources`, a case variant of a protocol or standard claim (`SUB`, `Email`) or of another entry (`tenant`, `Tenant`) | accepted (published, never emitted) | `New` fails |
| `Config.ClaimsSupported` with a protocol or standard claim spelled exactly (`sub`, `email`) | published | unchanged (published once) |

To migrate:

1. Remove from `Config.ClaimsSupported` the claims the provider never
   releases (`azp`, `jti`, `sid`, `nbf`, `cnf`, `scope`, `client_id`, `typ`,
   `c_hash`, `s_hash`, `_claim_names`, `_claim_sources`) and every case
   variant of a protocol, standard or other entry's claim.
2. Declare there every application claim relying parties make decisions on:
   its spelling becomes the only one released. An undeclared claim is still
   released under another spelling when requested alone, and dropped when
   requested together with such a variant.
3. A `ClaimsSource` exposing attribute names end-users choose keeps them
   apart from the names relying parties consume — a collision-resistant
   prefix (Core §5.1.2), or out of the release set — and treats
   `ClaimsQuery.Names` as untrusted input in directory or database lookups.
4. Relying parties key accounts on (`iss`, `sub`) only (Core §5.7), and
   decode tokens strictly (`oidc/client` refuses case-variant member names).

### `oidc/provider`: `offline_access` needs the decision's grant on every request

OIDC Core §11 binds OpenID requests only, and the provider applied it to them
only: a plain OAuth 2.0 request (no `openid`) for `offline_access` kept it as
the `Interaction` approved it, and `Request.OfflineAccess` was never set for
one — an application had to parse `Request.Scopes` to even notice. With
`grant.Config.RefreshTokenScope = offline_access`, an approval meant for
something else (a consent remembered per client, a page that never offered
the choice) handed out a refresh token: `examples/oidc-provider` did, even
right after the end-user had declined offline access. `offline_access` now
has one meaning at the provider's server:

| Request served by `Provider.AuthorizeHandler` | Before | After |
| --- | --- | --- |
| plain OAuth 2.0, `offline_access` requested | `Request.OfflineAccess` false | true |
| plain OAuth 2.0, `Decision.OfflineAccess` unset | `offline_access` granted | dropped from the grant (no refresh token with `RefreshTokenScope = offline_access`) |
| plain OAuth 2.0, only `offline_access` requested, `Decision.OfflineAccess` unset | code issued | `access_denied`, nothing issued |
| plain OAuth 2.0, `OfflineAccessPrompted` or `OfflineAccessByPolicy` | granted | granted (`prompt=consent` is not required: no OAuth 2.0 parameter) |
| OpenID request | §11 rules | unchanged |
| plain OAuth 2.0 request approved by another `ConsentFunc` (`Server().AuthorizeHandler`) | OAuth 2.0 semantics | unchanged |

Only the scope is gated: a plain OAuth 2.0 grant carries no provider context,
so its refresh tokens still follow `grant.Config.RefreshTokenScope` alone.

To migrate:

1. In the `Interaction`, ask the end-user about offline access whenever
   `Request.OfflineAccess` is set — for an OpenID request only with
   `prompt=consent` (Core §11) — and set `Decision.OfflineAccess =
   OfflineAccessPrompted` when she grants it. Never grant it from a
   remembered consent: "a previously saved user consent is not always
   sufficient to grant offline access" (§11).
2. To keep the former behaviour for plain OAuth 2.0 clients whose refresh
   tokens need no end-user choice, set `Decision.OfflineAccess =
   OfflineAccessByPolicy` for them, as a documented policy.
3. An `Interaction` that read `Request.OfflineAccess` as "an OpenID request
   with offline_access" also checks `Request.OpenID`.
