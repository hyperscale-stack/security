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
