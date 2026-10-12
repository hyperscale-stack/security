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
jwt/                    ← core + bearer + oauth2 + go-jose/v4 + otel
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
   its `GrantTypeValues`: an empty list allows every grant, and the server
   does not yet refuse `client_credentials` to public clients (RFC 6749
   §4.4).
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
