# Migration & workspace layout

The repository hosts **one** Go workspace (`go.work`) and **several** Go modules.
This layout lets consumers import only the pieces they need, keeps the core
free of heavy transitive dependencies, and lets each module be tagged and
released on its own cadence.

## Modules

| Path                      | Module                                                          | Purpose                                                              |
| ------------------------- | --------------------------------------------------------------- | -------------------------------------------------------------------- |
| `.`                       | `github.com/hyperscale-stack/security`                          | Core: transport-agnostic primitives (Authentication, Engine, Voter…) |
| `./http`                  | `github.com/hyperscale-stack/security/http`                     | `httpsec` — `net/http` adapter                                       |
| `./grpc`                  | `github.com/hyperscale-stack/security/grpc`                     | `grpcsec` — gRPC unary/stream interceptors                           |
| `./connectrpc`            | `github.com/hyperscale-stack/security/connectrpc`               | `connectrpcsec` — ConnectRPC auth + authorize interceptors           |
| `./basic`                 | `github.com/hyperscale-stack/security/basic`                    | HTTP Basic extractor + authenticator                                 |
| `./bearer`                | `github.com/hyperscale-stack/security/bearer`                   | Bearer extractor + `TokenVerifier`-based authenticator               |
| `./password`              | `github.com/hyperscale-stack/security/password`                 | BCrypt + Argon2id hashers                                            |
| `./jwt`                   | `github.com/hyperscale-stack/security/jwt`                      | `jwtsec` — JWT signer/verifier + JWKS                                |
| `./session`               | `github.com/hyperscale-stack/security/session`                  | Stateless encrypted cookie sessions + CSRF                           |
| `./oauth2`                | `github.com/hyperscale-stack/security/oauth2`                   | OAuth2 server (profiles, grants, endpoints)                          |
| `./oauth2/store/sql`      | `github.com/hyperscale-stack/security/oauth2/store/sql`         | Production storage on `database/sql`                                 |
| `./oauth2/store/redis`    | `github.com/hyperscale-stack/security/oauth2/store/redis`       | Production storage on Redis (Lua atomicity)                          |
| `./examples`              | `github.com/hyperscale-stack/security/examples`                 | Runnable use-case demos (one sub-package per scenario)               |
| `./internal/integrations` | `github.com/hyperscale-stack/security/internal/integrations`    | Cross-module end-to-end tests (private)                              |

`oauth2/storage/memory` is a sub-package of the `oauth2` module (not a
standalone module): it ships the in-memory `oauth2.Storage` used for dev
and tests.

The legacy v0 packages (`authentication/`, `authentication/credential/`,
`authentication/provider/{dao,oauth2}/`, `authorization/`, and the old
in-tree `password`) were removed during the rewrite. The core module now
depends only on stdlib + `go.opentelemetry.io/otel` (+ `testify` for its
own tests).

## Dependency policy

```
core (.)                ← stdlib + go.opentelemetry.io/otel
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
examples/               ← may depend on every module above

(`oauth2/storage/memory` is a sub-package of the `oauth2` module.)
```

The core MUST NOT depend on: gRPC, ConnectRPC, JWT/JOSE libs, OAuth2, Redis,
SQL drivers, HTTP routers, or concrete loggers. Its direct dependency set is exactly
stdlib + `go.opentelemetry.io/otel` (+ `stretchr/testify` scoped to its own
tests). The policy is enforced by review.

## Local development

```sh
make sync         # go work sync
make build        # build all modules
make test         # race + coverage, aggregated into build/coverage.out
make lint         # golangci-lint on every module with the shared config
make tidy         # go mod tidy on every module + go work sync
```

The `Makefile` discovers modules dynamically via `find . -name go.mod`, so a
new sub-module is picked up automatically as soon as its `go.mod` lands.
Example program lines are excluded from the aggregated coverage profile
(their `main()` is not unit-testable); the examples are still built, tested,
and linted.

## CI

`.github/workflows/go.yml` runs `make sync`, `make build`, `make test`, and
`make lint` against every module in one job, then publishes the aggregated
coverage to Coveralls. `.github/workflows/release.yml` validates the whole
workspace and publishes a GitHub release when a `module/vX.Y.Z` tag is
pushed.

## Replace directives

Every sub-module declares `replace github.com/hyperscale-stack/security => ../`
(or `=> ../../` for the SQL/Redis sub-modules) so local development and CI
work without published versions. Releases are cut per module with
`module/vX.Y.Z` tags.

## Breaking changes before the first v2 release

The v2 stack is not tagged yet, but code tracking `master` may already rely
on its behavior. Each entry below states what changed and how to adapt.

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
   comes with an error. A wrapper must propagate `err`; wrapping it with
   `%w` keeps the replay record reachable through `errors.As`.
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
