# Changelog

All notable changes to this project are documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The library is a multi-module workspace; modules are tagged independently
(`module/vX.Y.Z`), and the first release of every module is `v1.0.0`. The
entries below describe the ground-up rewrite that replaced the v0 stack.

## [Unreleased]

The whole `v0.x` series is superseded by a transport-agnostic rewrite. The
legacy packages (`authentication/`, `authorization/`, the in-tree
`password` package, `authentication/provider/oauth2`) were removed.

### Added

- **Transport-agnostic core** (`github.com/hyperscale-stack/security`):
  immutable `Authentication`/`Principal`, `Carrier`, `Extractor`,
  `Authenticator`, first-success-wins `Manager`, `Engine`, typed
  `SecurityError` sentinels, and a `Clock` abstraction.
- **Authorization**: `Voter`/`Decision`/`Attribute`, an
  `AccessDecisionManager` with Affirmative/Consensus/Unanimous strategies,
  and a `voter/` catalog (`HasRole`, `HasAnyRole`, `HasScope`,
  `HasAnyScope`, `HasAuthority`, `HasAnyAuthority`, `HasPermission`,
  `Authenticated`, `Anonymous`, `And`/`Or`/`Not`).
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
  enforced at runtime on the grants (PKCE required, `plain` PKCE refused,
  refresh-token rotation forced under BCP / 2.1). Grants:
  `authorization_code` (PKCE), `client_credentials`,
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
- **OAuth2 error hook**: `ServerConfig.OnError` and `grant.Config.OnError`
  (both `oauth2.ErrorHook`) observe every error the authorization server
  turns into an RFC 6749 §5.2 response — carrying the cause a `server_error`
  never puts on the wire — plus the errors behind an answer that cannot
  carry them, such as the storage failure behind a `/revoke` 503 or a family
  revocation that failed during reuse detection. Purely observational: the
  hook never changes a response.
- **OAuth2 profile consistency checks**: `oauth2.ProfileValidator`, an
  optional `Grant` capability: `oauth2.NewServer` asks every registered
  grant implementing it whether it can honor the active `Profile`, and
  refuses to build the server otherwise; the shipped `refresh_token` grant
  implements it. `grant.ErrRotationRequiresGenerator` reports a
  `refresh_token` grant that has to rotate refresh tokens but has no
  `grant.Config.RefreshTokens` generator to mint the replacement — returned
  by `NewServer`, and the cause of the `server_error` such a grant fails
  with at runtime, before any token is minted or persisted.
- **Observability**: OpenTelemetry spans emitted directly by the core,
  `httpsec`, `grpcsec`, `connectrpcsec`, `jwtsec`, and `session`. See
  [docs/observability.md](docs/observability.md).
- **Documentation**: `docs/architecture.md`, `docs/observability.md`,
  `docs/security-considerations.md`, `docs/migration-from-v0.md`, and a
  refreshed `README.md`.
- **OAuth2 introspection policy**: `ServerConfig.IntrospectionPolicy`
  (`oauth2.IntrospectionPolicy`) decides which active tokens each caller of
  `/introspect` may see — the place to enforce resource and tenant
  boundaries (RFC 7662 §4). It receives the request context, the
  authenticated confidential caller and an `oauth2.IntrospectedToken` (its
  `oauth2.TokenKind`, client, subject, scope, audience, issuance and expiry —
  never the token value). A denial answers a bare `{"active":false}`, the
  same bytes as an unknown token; a policy error fails closed the same way
  and reaches `OnError` as a `server_error`. Optional: without a policy, any
  authenticated confidential client may introspect any access token of the
  request's issuer, and the refresh tokens issued to it.
- **OAuth2 token-family primitives**: `oauth2.ErrTokenFamilyRevoked`
  (`invalid_grant`) refuses an operation on a revoked token family;
  `oauth2.ErrTokenFamilyRevocationFailed`, a plain sentinel that never
  reaches the wire, reports a family revocation that could not be recorded
  (the family must then be treated as active and the revocation retried);
  `oauth2.TokenPair.Validate` rejects a pair no store may persist (a refresh
  token outside the access token's family, without a family, or already
  consumed); `oauth2.MaxFamilyIDLength` (64 bytes) and
  `oauth2.FamilyRevocationRetention` (24h) bound family identifiers and how
  long a revoked family is remembered.
- **SAML 2.0 Service Provider** (`saml/sp`, package `samlsp`):
  SP-initiated Web Browser SSO for enterprise federation (Profiles §4.1).
  AuthnRequests over HTTP-Redirect, optionally signed (`rsa-sha256`);
  Responses over HTTP-POST. Connections are the application's
  (`ConnectionResolver`), each with its own SP entity ID, ACS URL, trusted
  `IdentityProvider` and SP metadata (`Metadata`, `ServeMetadata`); IdP
  metadata is imported with `ParseIdentityProviderMetadata`. A response
  passes a streaming lexical gate and a strict structural profile before
  gosaml2 v0.12.0 and goxmldsig v1.6.1 verify it: one assertion, signed
  Response or signed Assertion (errata E93/E26), an algorithm allowlist
  (SHA-1 only per connection, `InsecureAllowSHA1`), typed refusals of
  ambiguous shapes and of encrypted assertions. Login transactions are
  single-use and bound to the browser by a `__Host-` cookie; consumed
  assertions go to a replay cache. Every refusal matches `ErrRejected`,
  which wraps `security.ErrInvalidCredentials`; an IdP error status is a
  `*StatusError`. OpenTelemetry spans under the module's own scope.
- **SAML metadata retrieval**: `samlsp.FetchIdentityProviderMetadata`
  downloads an IdP's metadata from its configured https URL through the
  core `outbound` client (public destinations only, no redirect off the
  configured origin, bounded time and size), and `samlsp.MetadataSource`
  keeps it current for a resolver: pinned entity ID, refresh at the
  document's `cacheDuration` clamped to `[MinRefresh, MaxRefresh]` and
  when it expires, single-flight and rate-limited, in the background while
  a usable document is cached, which is served for at most `MaxStale`
  while refreshes fail and never past its `validUntil`. New sentinel
  `ErrMetadataUnavailable`.
- **SAML SP storage**: in-memory (`saml/sp/storage/memory`), SQL
  (`saml/sp/store/sql`, PostgreSQL/MySQL/SQLite) and Redis
  (`saml/sp/store/redis`, single-key Lua scripts), all validated by the
  shared `saml/sp/storetest` conformance suite.
- **SAML example and interoperability tests**: `examples/saml-sp`, and the
  private `internal/interop/saml` module, which runs the SP against
  crewjam/saml's IdP over TLS and replays a pinned Keycloak 26.0.7 login.
- **SAML adversarial and interoperability evidence** (#88), all in tests
  and documentation:
  - a pinned corpus of 390 entries over 360 signed responses
    (`saml/sp/testdata/corpus`) with a deterministic generator. Each entry
    pins its outcome — the full refusal message or the exact identity —
    and whether it consumed the login. A meta-test requires every refusal
    rule of the sources in some entry;
  - a live Keycloak 26.7.4 suite (opt-in, digest-pinned compose) and the
    replay of its 14 captures in CI, including XSW1–XSW8, signature removal
    and comment injection on Apache Santuario output;
  - races across Service Provider instances on shared SQL and Redis stores:
    SQLite and miniredis in CI, PostgreSQL, MySQL and Redis opt-in;
  - IdP metadata retrieval behind a Service Provider: key rollover, fetches
    driven by time only, entity pin, outbound refusals;
  - an opt-in browser suite (`make e2e`, Tales and Chrome) driving
    `examples/saml-sp` across sites: cross-site POST correlation, cookie
    tossing, login CSRF, RelayState integrity, open redirects;
  - the integration guide [docs/saml-sp.md](docs/saml-sp.md).
- **OAuth2 code replay error**: `oauth2.CodeReplayError`, the error an
  `AuthorizationCodeStore` returns for a replayed code it still retains. It
  matches `oauth2.ErrCodeAlreadyUsed` (`invalid_grant`) for `errors.Is`,
  `oauth2.IsCode` and the wire, and carries the retained record for
  `errors.As`.
- **Outbound HTTP guard** (`outbound`, a stdlib-only sub-package of the
  core): `outbound.NewClient(outbound.Policy)` returns the `*http.Client`
  the federation modules use for server-side requests to URLs that come
  from configuration or remote metadata (discovery documents, JWK Sets,
  token and UserInfo endpoints, SAML metadata), against server-side
  request forgery. Its zero-value policy allows https only (http is an
  opt-in, an https→http redirect is always refused), judges the address
  actually connected to — after DNS resolution, so DNS rebinding cannot
  bypass it — and refuses loopback, private (RFC 1918, RFC 4193), shared
  (RFC 6598), link-local and cloud-metadata, multicast, reserved,
  documentation and benchmarking space, IPv4-mapped and NAT64 addresses
  being judged on their IPv4 and IPv6 being limited to `2000::/3` minus
  its special-purpose blocks; it requires ASCII host names and refuses
  those ending in a number (`127.1`, `0x7f.1`, which resolvers read as
  IPv4 addresses) before the `CheckURL` hook, never names a refused
  address in an error, follows no redirect, uses no proxy and no cookie
  jar, bounds the exchange (10 s), the response headers (64 KiB) and every
  body (1 MiB, counted after decompression), and requires TLS 1.2 or
  later. Applications widen it explicitly (`AllowedPrefixes`,
  `AllowHTTP`, `MaxRedirects`) and narrow it with the `CheckURL` and
  `CheckAddr` hooks.
- **OpenID Connect Relying Party** (`oidc/client`, package `oidcclient`):
  logs users in through an OpenID Provider with the Authorization Code flow
  and returns a verified `Identity` (connection, issuer, subject, claims,
  tokens), one `Client` per connection. `New` discovers the provider (the
  metadata issuer must equal the configured one) through the `outbound`
  guard; `Begin`/`Complete` — or the net/http helpers `StartLogin`/
  `HandleCallback` — run the flow with PKCE S256, state and nonce, in the
  `query` or `form_post` response mode, with `client_secret_basic`,
  `client_secret_post` or a public client (`none`, which requires the
  provider to advertise S256). A login is bound to the user agent that
  started it: a 256-bit binding secret kept in an HttpOnly `__Host-` cookie
  (SameSite=Lax for `query`, None for `form_post`), from which the nonce and
  the PKCE verifier are derived, so the transaction store holds no secret,
  and which, with a server-held transaction key (`Config.TransactionKeys`,
  required), keys an integrity MAC over every field of the transaction
  (`Transaction.Integrity`, verified before any field is used: a
  transaction altered in the store fails with `ErrTransactionIntegrity`).
  The transaction is also bound to its connection, issuer, client, redirect
  URI and response mode, expires (10 minutes by default), and is consumed
  once. `Complete` requires the URL the response was received on
  (`Callback.URL`) to be the connection's redirect URI — scheme, host,
  port, path and the redirect URI's query parameters; a redirect URI
  distinct per connection is the mix-up defense (RFC 9700 §4.4.2.2) — and
  checks the RFC 9207 `iss` parameter when the provider advertises it;
  `HandleCallback` takes the host from the Host header and the scheme from
  the redirect URI, so that a TLS-terminating proxy preserving Host works. The ID Token is validated per OpenID Connect
  Core §3.1.3.7: an allow-listed asymmetric algorithm (RS*, PS*, ES*,
  EdDSA; HMAC and `none` refused), `typ` absent or JWT, iss, aud (extra
  audiences only if trusted), azp, exp/iat/nbf with a bounded skew, nonce,
  auth_time against `max_age`, acr against the requested `acr_values`, and
  at_hash. Keys come from the issuer's `jwks_uri` only, through a bounded
  cache (1 h TTL, one rate-limited refresh for an unknown `kid`,
  single-flight, 24 h stale limit). Every JSON document is parsed strictly
  (duplicate or case-variant member names refused at every level). Token
  and UserInfo requests never follow redirects. `UserInfo` returns claims
  only when their `sub` equals the identity's. Errors are sentinels
  (`ErrInvalidIDToken` and its causes, `ErrBindingMismatch`,
  `ErrTransactionNotFound`, `ErrIssuerParameter`, …) wrapping
  `security.ErrInvalidCredentials` where a credential is refused;
  `AuthorizationError` and `TokenError` carry the provider's error
  responses. Secrets never appear in errors, `String`/`GoString` or `slog`
  output.
- **OpenID Connect transaction stores**: the `oidcclient.TransactionStore`
  contract (`Save` never overwrites; `Consume` removes a transaction
  atomically and decides unknown, then expired, then binding mismatch,
  which keeps the transaction), with an in-memory store
  (`oidc/client/storage/memory`), a SQL store (`oidc/client/store/sql`,
  PostgreSQL/MySQL/SQLite, `PurgeExpired`) and a Redis store
  (`oidc/client/store/redis`, one Lua script per consumption, Redis Cluster
  compatible), all validated by the exported conformance suite
  `oidc/client/storetest`.
- **Bounded in-memory OpenID Connect transaction store**:
  `memory.WithCapacity(n)` (`oidc/client/storage/memory`) bounds the pending
  logins the store keeps; at capacity it drops the expired ones, then
  refuses with `memory.ErrFull` — in constant time, walking its
  transactions at most once per expiry — and never evicts a pending login.
  `n` must be at least 1 (`WithCapacity` panics otherwise).
- **OpenID Connect interoperability tests** (`internal/interop/oidcrp`,
  tests only): the Relying Party against the example provider of
  `github.com/zitadel/oidc/v3` — every client authentication method and
  response mode, UserInfo, callback replay, `prompt=none`, `max_age`, and
  the `acr_values` caveat (#86) — plus an opt-in browser test
  (`OIDC_BROWSER_TESTS=1`, headless Chrome) of the binding cookie's
  SameSite behavior. A pinned corpus of six real providers' discovery
  documents (Google, Microsoft Entra, Apple, GitLab, Salesforce, Auth0;
  `testdata/metadata`) checks every client profile against them (#86), and
  `OIDC_LIVE_DISCOVERY=1` reruns those checks against the live providers.
- **Real-backend runs of the OIDC client stores** (`internal/interop/oidcstack`,
  private and test-only, #86): the `oidc/client/storetest` conformance suite
  and a race of 120 consumers spread over four store instances — 20 rounds,
  a third with a wrong binding — on real PostgreSQL 16, MySQL 8.0 and
  Redis 7.4 (digest-pinned `compose.yaml`), opt-in through
  `OIDCCLIENT_POSTGRES_DSN`, `OIDCCLIENT_MYSQL_DSN`, `OIDCCLIENT_REDIS_ADDR`.
- **End-to-end tests of the OpenID Connect stack** (`internal/interop/oidcstack`,
  #85, #86): our Relying Party against our Provider over HTTP — every
  client authentication method (`client_secret_basic` with form-encoded
  credentials), root and path issuers (with a trailing slash too), the nine
  ID Token algorithms, `prompt`, `max_age`, `acr_values`, hints, consent
  denial, granted scope, refresh — and the attacks that must fail: mix-up
  with an attacker provider and between the issuers of one provider (RFC
  9207, RFC 9700 §4.4; the residual risk without `iss` is characterized), an
  issuer-bound client used at another issuer, re-signed or substituted ID
  Tokens, token and UserInfo responses, code injection, PKCE downgrade,
  callback and code replay, refresh-token reuse, key rotation and
  withdrawal windows, concurrent callbacks across replicas (on real
  PostgreSQL, MySQL and Redis too), and provider, store or network
  failures. The tests import no third-party OpenID Connect, OAuth 2.0 or
  JOSE library — the client's own go-jose is part of the code under test
  (`TestDependencyPolicy`).
- **OpenID Foundation conformance-suite harness**
  (`internal/interop/oidcstack/conformance`, `make conformance`, opt-in and
  local, never in CI; #86): the suite's OP plans (Basic under
  `oauth2.Profile20`, Config for a root and a path issuer) run against
  `oidc/provider` with a headless interaction, and its RP plans (Basic,
  Form Post Basic, Config, the comprehensive plan) against `oidc/client`
  through a Go driver of the suite's REST API that pins the suite's result
  and the client's outcome of every module. Images are pinned by digest,
  the expected failures, skips and outcomes live in `testdata`. A local run
  is not an OpenID Certification; its results are recorded in
  [docs/oidc-conformance.md](docs/oidc-conformance.md).
- **OpenID Connect documentation** (#86):
  [docs/oidc-conformance.md](docs/oidc-conformance.md) — the cross-cutting
  requirements matrix with the tests behind every row, what is not
  supported, the independent implementations, the attack catalogue, the
  end-to-end and conformance-suite runs with their gaps, and the release
  checklist; [docs/oidc-client.md](docs/oidc-client.md) — the Relying
  Party's feature matrix and integration guide (connections and redirect
  URIs, callback and session, several instances, the provider-key
  timetable, account linking, refresh tokens);
  `docs/security-considerations.md` — protocol validation versus
  application policy. `TestDocumentedTestsExist` keeps the cited tests
  real and the pages free of certification claims.
- **End-to-end suites of the OpenID Connect examples** (`e2e/oidc`, Tales,
  opt-in through `make e2e-oidc`, never in CI; #85, #86):
  `examples/oidc-provider` and `examples/oidc-client` built and started on
  two loopback sites — provider scenarios over HTTP (discovery and JWK Set,
  code flow with PKCE, UserInfo, code replay, `prompt`, `max_age`, consent,
  offline access, refresh rotation and reuse, refused requests, the login
  and consent pages' hardening), the relying party's callback binding,
  and a real Chrome: consent denied then given, sign-out, single sign-on,
  cross-site form posts refused. Only the configuration and four keywords
  are specific to the examples, so the provider scenarios can run against
  another provider. `make e2e-oidc-live` signs in with a real provider
  account (`LIVE_OIDC_*`, a person at the keyboard).
- **Example** `examples/oidc-client`: sign-in through several connections
  with distinct callback routes, account linking on (connection, issuer,
  subject), and a local session. `OIDC_DEV_ALLOW_LOOPBACK=1` (development
  only) lets it reach a provider on the loopback interface over plain http
  — `examples/oidc-provider`, which it runs against out of the box (#86).

- **OAuth2 protocol extension points** (`oauth2`): `ServerConfig.Extension`
  takes an `oauth2.Extension` — the contract an OpenID Provider (the
  `oidc/provider` module) builds on, without a second `/token` endpoint and
  without `oauth2` depending on OIDC or JOSE. `ValidateAuthorizeRequest`
  validates the extension's own `/authorize` parameters after every core
  check, its view reaching the `ConsentFunc` as
  `AuthorizeRequest.ExtensionRequest`; `CompleteAuthorization` turns the
  application's trusted result (`Consent.ExtensionResult`) into an
  `oauth2.ExtensionGrant` — a scope that can only narrow the grant, and
  opaque `Data` (at most `oauth2.MaxExtensionDataLength`, 4096 bytes of UTF-8
  without NUL) recorded on the code and on every token derived from it, the
  same across refreshes (OIDC Core §12.2, RFC 9068 §2.2.1);
  `ExtendTokenResponse` runs in the `authorization_code` and `refresh_token`
  grants between minting the tokens and their single atomic write, with a
  copy of the access token (OIDC Core §3.1.3.6 `at_hash`), the grant context,
  the code's nonce and whether a refresh token comes with the access token
  (`RefreshTokenIssued`, so an OpenID provider can fail closed on a refresh
  token issued without `offline_access` consent, OIDC Core §11), and returns
  an `oauth2.TokenResponseExtension` whose
  `IDToken` becomes the `id_token` member (`GrantResponse.IDToken`). The RFC
  6749 §5.1 members cannot be overwritten, and no response is partially
  successful: a hook failure persists nothing, and an `id_token` only travels
  with a persisted pair. `GrantRequest.Extension` carries the hook to the
  grants; `oauth2.GrantTypeAuthorizationCode` / `GrantTypeRefreshToken` name
  the exchanges; `oauth2.ErrUnredirectableRequest` lets a hook refuse
  without redirecting; `oauth2.ErrAuthorizeRequestModified` is the cause
  reported when a callback modified the read-only request it was handed.
  See `ExampleExtension`.
- **OAuth2 consent refusals**: `Consent.Refusal` redirects an
  authorization-endpoint error instead of `access_denied` — e.g.
  `oauth2.ErrLoginRequired`, `ErrConsentRequired`, `ErrInteractionRequired`,
  `ErrAccountSelectionRequired`, the new `Code*` constants and `Err*`
  sentinels for the nine OIDC Core §3.1.2.6 codes (`ErrRequestNotSupported`,
  `ErrRequestURINotSupported`, `ErrRegistrationNotSupported`,
  `ErrInvalidRequestURI`, `ErrInvalidRequestObject`).
- **OAuth2 grant context on codes and tokens**: `AuthorizationCode`,
  `AccessToken` and `RefreshToken` gain `Issuer` and `ExtensionData`;
  `AuthorizeRequest.Issuer` and `IntrospectedToken.Issuer` expose the realm,
  which `/introspect` and `/revoke` enforce (see Changed).
- **OAuth2 refresh-token gate**: `grant.Config.RefreshTokenScope` makes the
  `authorization_code` and legacy `password` grants issue a refresh token
  only when the granted scope holds that scope token — e.g.
  `offline_access` (OIDC Core §11). Opt-in; rotation is unaffected.
- **JWT key publication and signature-only verification** (`jwtsec`):
  `MarshalJWKS` serializes an RFC 7517 JWK Set of public signature keys —
  every key with a unique `kid`, its `alg` and `use: sig` — and refuses
  private or symmetric material, publishing nothing (OIDC Discovery §3);
  `PublicKey.Validate`, `PrivateKey.Validate` and `PrivateKey.Public` bind a
  key to its algorithm (RSA of at least 2048 bits for RS*/PS*, the matching
  curve for ES*, Ed25519 for EdDSA — RFC 7518 §3.3–§3.5, RFC 8725 §3.1);
  `VerifySignature` verifies a compact JWS against a key list (allowlisted
  `alg`, key selected by `kid` and bound to that `alg`) and returns its
  header and payload without validating any claim, for callers applying
  their own claim rules. `ErrInvalidKey` reports an unfit key.
- **JWT explicit typing** (`jwtsec`): `WithType` sets the `typ` header a
  `Signer` writes (`TypeJWT` by default) and makes a `Verifier` require it,
  compared as RFC 7515 §4.1.9 prescribes (case-insensitive, `application/`
  implied) — `ErrInvalidType` otherwise; opt-in on verifiers.
- **OAuth2 issuer identification in authorization responses** (RFC 9207):
  every authorization response — code and implicit, success and redirected
  error — carries `iss`, the issuer the request resolved to, and the RFC 8414
  metadata publishes `authorization_response_iss_parameter_supported: true`,
  so a client talking to several authorization servers or realms can detect
  a mix-up (RFC 9700 §4.4.2.1). The `server_error` answering an
  `IssuerResolver` failure is the one response without it.
- **OAuth2 client ↔ issuer binding**: `oauth2.IssuerBoundClient`
  (`AllowsIssuer`), an optional client capability — implemented by
  `DefaultClient` through `IssuerValues` — for deployments whose
  `IssuerResolver` serves several issuers from one `ClientStore`. At an
  issuer it is not registered at, a client does not exist: `/authorize`
  answers the bare 400 of an unknown client, never redirected, and `/token`,
  `/revoke` and `/introspect` fail its authentication as an unknown
  client's (`401 invalid_client`), whatever the secret — so another realm's
  clients can be neither used nor enumerated. `oauth2.ClientAllowsIssuer`
  applies the rule; `oauth2.ErrClientNotAtIssuer` is the cause `OnError`
  gets. The server now resolves the issuer before it loads the client, at
  every endpoint `/revoke` and `/introspect` included (see
  [MIGRATION.md](MIGRATION.md)).
- **OpenID Provider** (`oidc/provider`, package `oidcprovider`): OpenID
  Connect Core 1.0 (errata set 2) on the `oauth2` extension points — the
  Authorization Code flow with PKCE, signed ID Tokens at the code exchange
  and at every refresh (Core §12.2: the original `auth_time`, `acr` and
  `amr`, no `nonce`), UserInfo (Core §5.3, RFC 6750 errors), Discovery
  (path issuers, only what is served, consistent with RFC 8414) and the
  issuer's public JWK Set. `New` builds the `oauth2.Server` it extends,
  `Paths` tells where to mount each handler. The provider validates
  authentication requests — `prompt`, `max_age`, `nonce`, the `claims`
  parameter, `id_token_hint`; `request`, `request_uri` and `registration`
  refused with their Core §3.1.2.6 codes — and re-checks every approval
  itself: realm, `prompt=login` and `max_age` freshness, designated
  end-user, essential `acr`, `offline_access` consent (Core §11). The
  application keeps the end-user side through typed interfaces:
  `Interaction` (login and consent UI; `prompt=none` gets no
  `ResponseWriter`), `ClaimsSource` (released claims only;
  `ErrUnknownSubject` stops a grant) and `KeySource` (rings validated on
  every use: RS256 required, RSA of at least 2048 bits, private keys never
  published). Access-token audiences equal to a client ID are refused
  (RFC 9068 §5). [docs/oidc-provider.md](docs/oidc-provider.md) is the exact
  feature matrix; no certification is claimed.
- **OpenID Provider interoperability tests** (`internal/interop/oidcop`, private and
  test-only): the provider against `github.com/coreos/go-oidc/v3` and
  `golang.org/x/oauth2` as an independent relying party, over TLS — code
  flow with S256 PKCE, the three client authentication methods, path
  issuers, refresh, key rotation, `prompt=none` and the advertised URLs;
  and (#86) the `claims` parameter with consent filtering, a narrowed
  granted scope, re-authentication (`prompt=login`, `max_age`),
  `id_token_hint`, PS256/RS512/ES256/ES384 ID Tokens verified by go-oidc,
  RFC 9068 access tokens refused by go-oidc's ID Token verifier (audience),
  code replay and refresh-token reuse revoking the tokens.
- **Example** `examples/oidc-provider`: a runnable OpenID Provider with its
  own login and consent pages (CSRF tokens, anti-framing headers),
  cookie sessions, `prompt` handling and offline access. Its issuer,
  listen address and clients' redirect URI come from
  `OIDC_PROVIDER_ISSUER`, `OIDC_PROVIDER_ADDR` and
  `OIDC_PROVIDER_REDIRECT_URI`; the default redirect URI is the callback of
  the `demo` connection of `examples/oidc-client` (#86).
- **OAuth2 absolute refresh-family lifetime**: `grant.Config.RefreshFamilyTTL`
  (opt-in, zero by default) bounds a refresh-token family's lifetime from its
  first issuance, which refresh tokens now record
  (`oauth2.RefreshToken.FamilyIssuedAt`, carried unchanged by every rotation):
  no refresh token outlives the deadline and a later refresh is
  `invalid_grant`. `RefreshTTL` keeps its inactivity semantics (RFC 9700
  §4.14.2).
- Core sentinels `security.ErrAuthenticationRequired` (no credential the
  server could validate, or an unauthenticated principal refused by an
  access decision), `security.ErrInvalidRequest` (a malformed authentication
  request, such as a repeated `Authorization` field) and
  `security.ErrUnavailable` (the credentials could not be checked because a
  dependency — key set, user store, introspection endpoint — is temporarily
  unavailable; not a verdict on the credentials).
- `security.ErrorClass(err)` and the `security.ErrorClass*` constants: one
  classification of security errors — joined errors included — shared by
  the core spans (`error.type`) and the default HTTP, gRPC and ConnectRPC
  error mappers; custom error mappers should use it too.
- `security.StateAttribute` with `security.IsAuthenticated` and
  `security.IsAnonymous`: the attributes `voter.Authenticated()` and
  `voter.Anonymous()` vote on.
- `security.RolePrefix` (`ROLE_`) and `security.ScopePrefix` (`scope:`): the
  authority namespaces the voter package matches roles and scopes in.
- `httpsec.Carrier.CookiesNamed` and `session.CookieReader`: the explicit
  accessor the session `Manager` reads its cookie through.
- `security.SingleValue(carrier, key)`: the value of a singleton header
  field, refusing a repeated one with `ErrInvalidRequest`; the Basic and
  Bearer extractors read `Authorization` through it. `httpsec.DefaultRealm`
  (`api`).
- `grpcsec.ServerOptions` and `grpcsec.AuthorizeServerOptions`: the
  authentication and authorization interceptors for unary AND streaming
  RPCs, as `grpc.ServerOption` values.
- `connectrpcsec.WithChallengeScheme`, `connectrpcsec.WithRealm` and
  `connectrpcsec.DefaultRealm`: the challenge of the Connect error mapping.
- **JWT verification bounds and remote key sets** (`jwtsec`):
  `DefaultMaxTokenSize` and `WithMaxTokenSize` (the largest token a
  `Verifier` parses, 16 KiB by default); `MaxClockSkew`;
  `WithOutboundPolicy` (the SSRF policy of `NewRemoteJWKS`), the refresh
  policy constants `DefaultCacheTTL`, `MinKeySetRefreshInterval`,
  `MaxKeySetStaleness`; `BearerOption` and `WithAccessTokenType`;
  `ErrInvalidClaims`, `ErrUnsignableClaims`, `ErrKeySetUnavailable` (wraps
  `security.ErrUnavailable`); a
  `jwtsec.RemoteJWKS.Fetch` span; fuzz targets for the verifier, the claims
  decoder and NumericDate. See Security and Changed.
- **OAuth2 request bounds**: `oauth2.ServerConfig.MaxRequestBytes` (default
  `oauth2.DefaultMaxRequestBytes`, 64 KiB) bounds the query and the body of
  every endpoint; `oauth2.MaxNonceLength` (512), `oauth2.MaxStateLength`
  (4096) and `oauth2.MaxClientIDLength` (255) document the bounds of the
  values the server keeps, echoes or looks up.
- **`oauth2.ValidateRedirectURI`** (and `oauth2.ErrInvalidRedirectURI`)
  checks a redirect URI at registration — absolute, no fragment, host and no
  userinfo for http(s), "." in a private-use scheme (RFC 8252 §8.4), no
  response parameter in its query; `/authorize` applies it to the URI a
  request resolves to.
- **`oauth2.AuthorizeConfig.TrustedRedirect`**: for a client it does not
  trust, the errors `/authorize` detects before the resource owner
  authenticated — and `prompt=none`-style refusals (`login_required`,
  `interaction_required`, `account_selection_required`, `consent_required`)
  — are answered with a bare error page instead of a redirect (RFC 9700
  §4.11.2). Without it, every registered client is trusted, as before.

### Changed

- `examples/oidc-client` bounds its unauthenticated login starts: each
  client (an IPv4 address, an IPv6 /64) may start 20 logins a minute and
  each network (an IPv4 /24, an IPv6 /48) 60 — `429 Too Many Requests`
  with `Retry-After` beyond — and the in-memory store keeps at most
  10 000 pending logins (`memory.WithCapacity`) — `503 Service
  Unavailable` beyond —, so that one network holds at most about 600 of
  them. It used to accept and keep every start for ten minutes.
- `oidc/client/storage/memory.New` takes options: `New(opts ...Option)`.
  Calls are unchanged; code using `memory.New` as a `func() *memory.Store`
  value needs a closure. Its periodic sweep now walks the transactions only
  once one may have expired.
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
- **OAuth2 storage contract (breaking).** `oauth2.Storage` drops
  `SaveAccessToken` and `SaveRefreshToken` for `SaveTokenPair`, which
  persists a newly issued pair atomically; `RotateRefreshToken` takes the
  whole replacement `*oauth2.TokenPair` and persists it atomically with the
  consumption of the presented token; `RevokeRefreshFamily` records a family
  revoked even before any of its tokens exists, is idempotent, and rejects
  an empty or over-long ID with `invalid_request`. Every store keeps one
  authoritative state per token family that issuance, rotation and lookups
  go through: a token of a revoked family is no longer usable — its access
  token lookup fails with `invalid_grant`, its refresh token reads consumed
  — and nothing can be issued into it. Access and refresh tokens must share
  one backend. `store/sql` adds the `oauth2_token_families` table (`Migrate`
  creates it); `store/redis` replaces the `famrt:`/`famat:` sets with one
  `fam:{id}` key per family and now requires Redis 6.0 or later
  (`SET … KEEPTTL`) and `maxmemory-policy noeviction`. The guarantees are
  documented on `oauth2.Storage` and checked by `oauth2/storetest`, which
  every implementation must pass. Upgrading invalidates every refresh token
  and every family-bound access token issued before it — their family has no
  record and the stores fail closed — so users re-authenticate, and
  presenting such a refresh token answers `invalid_grant`;
  `client_credentials` and implicit tokens keep working. See
  [MIGRATION.md](MIGRATION.md).
- **OAuth2 authorization-code storage (breaking).**
  `ConsumeAuthorizationCode` no longer deletes the code it consumes: every
  store keeps the record, flagged consumed and without the raw code, at
  least until the code expires, and answers a replay with an
  `*oauth2.CodeReplayError` carrying it; an unknown code still gets
  `ErrCodeAlreadyUsed`. `store/sql` adds a `consumed` column to
  `oauth2_auth_codes` — existing tables need an `ALTER TABLE` — and keeps
  consumed rows until the operator's cleanup; `store/redis` flags the
  code's key and keeps its TTL, and a consumption resent by go-redis after
  a lost reply no longer fails the exchange; the memory store no longer
  keeps the raw code. Every instance must be upgraded at once. See
  [MIGRATION.md](MIGRATION.md).

- **OAuth2 codes and tokens carry an issuer and a grant context
  (breaking).** `AuthorizationCode`, `AccessToken` and `RefreshToken` gain
  `Issuer` and `ExtensionData`, which every store persists byte-exact and
  returns from every read. `TokenPair.Validate` refuses a refresh token whose
  issuer or extension data differ from its access token's, and
  `RotateRefreshToken` refuses, with `invalid_request` and without writing
  anything, a replacement whose issuer or extension data differ from the
  presented token's. `store/sql` adds nullable `issuer` and `extension_data`
  `TEXT` columns to the code and token tables — `Migrate` creates them for new
  installs only, existing databases apply the `ALTER TABLE` statements of
  [MIGRATION.md](MIGRATION.md) (an optional single-issuer backfill keeps users
  signed in); `store/redis` adds optional payload fields. Every instance must
  be upgraded at once.
- **JWT access tokens follow RFC 9068 (breaking)**:
  `jwtsec.NewOAuth2AccessTokenSigner` takes the `PrivateKey` and builds its own
  signer, so every access token is typed `at+jwt` (RFC 9068 §2.1) — a resource
  server verifying with `WithType(TypeAccessToken)` refuses an OpenID Connect
  ID Token signed by the same keys — and carries a random 128-bit `jti`
  (§2.2). It used to wrap any `Signer` and emit `typ: JWT` without `jti`. See
  [MIGRATION.md](MIGRATION.md).
- **OAuth2 `GrantResponse.ExtraParams` removed (breaking)**: it was never
  serialized. `GrantResponse.IDToken` is the typed member a token response
  may add (`id_token`).
- **OAuth2 `/authorize`** resolves the issuer right after the redirect URI is
  trusted, for both flows: a resolver failure answers a redirected
  `server_error` before the `ConsentFunc` runs. The request a `ConsentFunc`
  — or an extension hook — gets is a read-only copy: modifying any field of
  it but `ExtensionRequest`, or the identity of the client it shares, fails
  the authorization with `server_error` (`oauth2.ErrAuthorizeRequestModified`
  at `OnError`) and issues nothing — breaking for a `ConsentFunc` that
  narrowed the grant by rewriting `ar.Scope`, which must use
  `Consent.Scope`; on master the server read the rewritten request back. The
  code is bound to the client ID read at validation. An approval must name
  its subject — non-empty, at most 255 bytes (OIDC Core §2) — or it is
  answered `server_error` and issues nothing (breaking for `ConsentFunc`s
  approving without one). A `ConsentFunc` error still answers `server_error`,
  whatever the error, and its cause now reaches `OnError`.
- **`oidcclient.Config.TransactionKeys` is required** (#86, breaking): 1 to
  4 server-held keys of at least 32 bytes, shared by every instance serving
  callbacks; the first protects new login transactions, all are accepted
  (rotation). `New` fails with `ErrInvalidConfig` without them, and the
  logins in flight during the upgrade fail once with
  `ErrTransactionIntegrity`. `Config` and `*Client` now print and log
  without the client secret and the keys, whatever the `fmt` verb. The example
  reads `OIDC_TRANSACTION_KEYS`. See [MIGRATION.md](MIGRATION.md).
- **Go 1.27.2 minimum** (breaking): every module and `go.work` declare
  `go 1.27.2`, so no consumer can build the library with a toolchain that
  carries the standard-library advisories of go1.26.5, the version CI tested
  with until now (HTTP/2 crashes, request smuggling, `crypto/tls`,
  `encoding/asn1`; govulncheck finds none on go1.27.2). CI runs the version
  `go.work` names. See [MIGRATION.md](MIGRATION.md).
- **Module and release checks**: `make check-modules` (run by CI) fails
  unless `go.work` and every `go.mod` share one `go` line, `go.work` lists
  every module, `go work sync` changes nothing and every module builds, vets
  and is tidy on its own (`GOWORK=off`). `make release-check TAG=…` (also run
  by the release workflow) accepts only canonical `v1.x.y` tags of released
  modules, refuses placeholder requirements and commits off `master`, and
  builds the module as a consumer resolves it, without its in-repo
  `replace` directives. The first release of every module is `v1.0.0`; the
  checklist is [docs/releasing.md](docs/releasing.md).
- **Development tools in their own modules**: golangci-lint (v2.14.0, Go
  1.27 support), govulncheck (v1.9.0), goveralls (v0.0.12) and mockery
  (v3.8.1) are pinned in one module each under `tools/`, outside `go.work`.
  The core module no longer declares the mockery `tool` directive: a
  consumer importing only the core now resolves 23 modules instead of 50,
  both counts including the consumer (no mockery, cobra, viper, zerolog or
  `x/tools`). `make lint` builds golangci-lint from its pinned module instead
  of piping an unpinned install script (`curl …/HEAD/install.sh | sh`).
- **Mocks are generated, never committed**: `make generate` (mockery v3,
  testify template) writes in-package `mock_<interface>_test.go` files, which
  exist only in test binaries; `make test`/`lint`/`vuln`/`tidy` and CI run it
  first. New tests use them for interface doubles. A module that gets mocks
  keeps a `mockery_test.go` importing `testify/mock`, so its `go.mod` is the
  same with or without them (`github.com/stretchr/objx` becomes an indirect
  requirement).
- **OAuth2 scope values are parsed strictly (breaking)**: the `scope` of
  `/authorize` and `/token`, `Consent.Scope` and `ExtensionGrant.Scope` are
  read as RFC 6749 §3.3 tokens — printable ASCII but `"` and `\`, separated by
  SP — at most 100 tokens and 4096 bytes; anything else is `invalid_scope`
  (`server_error` for an extension). Scopes are issued and stored canonical,
  duplicates dropped, refresh narrowing included, and the `/token`
  `invalid_scope` description no longer echoes the request. See
  [MIGRATION.md](MIGRATION.md).
- **OAuth2 clients get only what they declare (breaking)**: an empty
  `Client.GrantTypes()` allows no grant and an empty `Client.Scopes()` no
  scope — both meant "anything" before. `/token` checks the client's grant
  types for every grant, custom ones included, before the grant runs
  (`unauthorized_client`; a code or refresh token presented stays untouched),
  and a code exchange or password grant issues a refresh token only to a
  client declaring `refresh_token`. Refusals caused by an empty declaration
  carry `oauth2.ErrNoGrantTypesDeclared` / `oauth2.ErrNoScopesDeclared` to
  `OnError`. New: `oauth2.ClientAllowsGrantType` and the `GrantTypeImplicit`,
  `GrantTypeClientCredentials`, `GrantTypePassword` constants. Every client
  must declare its grant types and scopes. See [MIGRATION.md](MIGRATION.md).
- **OAuth2 `AuthorizationCode.RedirectURIOmitted` (storage, breaking for
  custom stores and SQL schemas)**: codes record whether the authorization
  request named a `redirect_uri`; every store persists the flag
  (`store/sql`: a `redirect_uri_omitted SMALLINT NOT NULL DEFAULT 0` column
  existing databases add with the `ALTER TABLE` of
  [MIGRATION.md](MIGRATION.md)).
- **OAuth2 `RefreshToken.FamilyIssuedAt` (storage, breaking for custom stores
  and SQL schemas)**: every store persists it (`store/sql`: a
  `family_issued_at BIGINT NOT NULL DEFAULT 0` column existing databases add
  with the `ALTER TABLE` of [MIGRATION.md](MIGRATION.md)).
- `Engine.Process` and `Manager.Authenticate` return `security.Anonymous()`
  on every failure, and the Engine stores the anonymous authentication in
  the returned context: the extracted credentials never flow back to the
  caller. The `Manager` treats an authenticator error wrapping
  `ErrUnsupportedCredential` — and no higher-ranked sentinel — as an
  abstention (the documented runtime bail-out) rather than a refusal joined
  with the others, and a "success" without an authenticated value as a
  refusal. A typed nil (an interface holding a nil pointer) counts as nil
  wherever the core checks a contract. `NewEngine`, `NewManager`
  and the three `AccessDecisionManager` constructors panic on a nil
  dependency. See [MIGRATION.md](MIGRATION.md).
- Failing core spans (`security.Engine.Process`,
  `security.Manager.Authenticate`, `security.AccessDecisionManager.Decide`)
  record the class of their error as status description and `error.type`
  attribute, and no longer add an `exception` event.
- Voters follow Spring Security's semantics: each votes only on the
  attributes whose family and value it supports (`HasRole("ADMIN")` abstains
  on `Role("USER")`), `HasAny*` grants for the requested names only,
  `Authenticated()`/`Anonymous()` vote only on `security.IsAuthenticated` /
  `security.IsAnonymous`, `voter.And` is strict (an inner abstention denies
  when the composite votes), `voter.Not` never grants an unauthenticated
  principal, and the decision managers deny an attribute that no voter
  supports — and a decision without attributes or voters whatever the
  tie-break and abstain fallback — and pass each voter only the attributes
  it supports. `And`, `Or`
  and `Not` panic on a nil or missing voter. See
  [MIGRATION.md](MIGRATION.md).
- Roles and scopes live in their own authority namespaces: `voter.HasRole`
  matches only `ROLE_<name>` and `voter.HasScope` only one `scope:<name>`
  per authority. A bare `admin` authority no longer satisfies
  `HasRole("admin")` and `HasScope("admin")`, and `scope:a b` is no longer
  split into two scopes. The voter constructors panic on a name they could
  never match: none, an empty one, a role starting with `ROLE_`, a scope
  that is not an RFC 6749 §3.3 scope-token or starts with `scope:`. See
  [MIGRATION.md](MIGRATION.md).
- `httpsec.Carrier.Get` and `Values` read the request's header fields only;
  they no longer fall back to a cookie or to the query string named like
  the key. `session.Manager` reads its cookie through the carrier's
  `CookiesNamed` accessor (`session.CookieReader`) and finds no session with
  a carrier that lacks it. See [MIGRATION.md](MIGRATION.md).
- The HTTP error mapping follows RFC 6750, RFC 7617 and RFC 9110: every
  challenge carries a realm (`httpsec.DefaultRealm` unless `WithRealm`), a
  Basic one `charset="UTF-8"`, the realm is an RFC 9110 quoted-string
  (`Middleware` and `DefaultErrorMapper` panic on a realm one cannot carry or
  a scheme that is not a token); `invalid_token` answers every failed check
  of a bearer token and `insufficient_scope` every 403 of a request made
  with one, and no RFC 6750 code is sent for other requests; an unsupported
  credential is 401 without error code (was 400), an unauthenticated
  principal refused by `Authorize` 401 (was 403), a repeated `Authorization`
  field 400, an `ErrUnavailable` 503, and an error wrapping no sentinel 500
  (was 401); a Bearer resource challenges every refusal, 400 and 5xx
  included (RFC 6750 §3). `Authorize` answers with the challenge of the
  `Middleware` in front of it instead of a hard-coded bare `Bearer`, copies
  its attributes and panics on a nil one; `Middleware` panics on a nil
  engine. See
  [MIGRATION.md](MIGRATION.md).
- The `httpsec.Middleware` span records `http.request.method` (`_OTHER`
  for a method outside RFC 9110 / RFC 5789) instead of `http.method`, and
  `http.route` only as the `ServeMux` pattern's path template.
- The gRPC error mapping answers from `security.ErrorClass` with one
  generic message per code: an unsupported credential is `Unauthenticated`
  (was `InvalidArgument`), an anonymous principal refused by
  `UnaryAuthorize`/`StreamAuthorize` `Unauthenticated` (was
  `PermissionDenied`), a repeated `authorization` value `InvalidArgument`,
  an `ErrUnavailable` `Unavailable`, and an error wrapping no sentinel
  `Internal` (was `Unauthenticated`). The authorization interceptors use the
  authentication interceptor's error mapper unless given their own, copy
  their attributes and panic on a nil one; the authentication interceptors
  and `ServerOptions` panic on a nil engine.
- `connectrpcsec.DefaultErrorMapper()` becomes
  `DefaultErrorMapper(scheme, realm string)` and answers from
  `security.ErrorClass` like the gRPC mapper (generic messages,
  `Unauthenticated` for an unsupported credential and for an anonymous
  principal refused by the authorization interceptor, `InvalidArgument` for
  a repeated `Authorization` field, `Unavailable` for `ErrUnavailable`,
  `Internal` for an error wrapping no sentinel), with the RFC 6750 / RFC
  7617 `WWW-Authenticate` challenge in the error's metadata — on every
  refusal of a Bearer resource. The authorization interceptor uses the
  authentication interceptor's error mapper unless given its own, copies
  its attributes and panics on a nil one; `NewAuthenticationInterceptor`
  panics on a nil engine.
- **`jwtsec` hardening (breaking)** — see [MIGRATION.md](MIGRATION.md):
  - `NewSigner`, `NewOAuth2AccessTokenSigner` and `NewRemoteJWKS` return an
    error (`ErrInvalidKey`; `outbound.ErrURLNotAllowed`,
    `outbound.ErrInvalidPolicy`) instead of panicking or accepting anything;
  - `BearerVerifier` panics unless its verifier comes from `NewVerifier`
    with `WithIssuer`, `WithAudience`, `WithType(TypeAccessToken)` (or the
    type of `WithAccessTokenType`) and a required `exp`, and refuses tokens
    without `sub`; the bearer examples sign RFC 9068 access tokens;
  - every verification key must set `Algorithm` and, when asymmetric, pass
    `PublicKey.Validate`; a `kid` shared by several keys designates none;
  - claims and `claimsOut` are decoded case-sensitively by go-jose's
    decoder; duplicate and case-folding-equal claim names are refused;
  - tokens over 16 KiB, non-canonical encodings and `crit`/`b64` headers
    are refused; `VerifySignature` reports a disallowed algorithm as
    `ErrAlgorithmNotAllowed`;
  - NumericDates outside 1970–9999 are refused both ways; `WithClockSkew`
    panics outside [0, 5 min]; `WithCacheTTL` outside (0, 24 h];
    `WithAudience` on an empty value;
  - `NewRemoteJWKS` refuses non-https, loopback and private destinations
    unless `WithOutboundPolicy` allows them, and follows redirects within
    the JWK Set URL's origin only; RFC 9068 access tokens need a non-empty
    audience from the `IssuerResolver`.

- **SAML Service Provider (breaking, security audit).** `samlsp.New`
  requires `Config.TransactionKeys` (1 to 4 keys of at least 32 bytes);
  `TransactionRecord` gains `Integrity`, which every store persists (SQL
  column `integrity`, Redis field `i`) and `Validate` requires; the payload
  must be 7-bit ASCII. A response refused after the binding and transaction
  checks consumes the transaction. A Success `Response` without
  `InResponseTo`, a request received on another host or with a query
  string, an `xml:` attribute outside the XML namespace's four names and an
  `EntitiesDescriptor` imported without a pinned entity ID are refused;
  `Connection.ACSURL` needs an ASCII host. New: `ErrTransactionIntegrity`,
  `ErrOriginMismatch`, `Connection.ResponseOrigins`,
  `MinTransactionKeySize`, `MaxTransactionKeys`, the span attribute
  `samlsp.transaction_consumed`. See [MIGRATION.md](MIGRATION.md).
- **`oidcprovider.Config.ClaimsSupported` is validated against the release
  rules** (breaking): `New` refuses the claims the provider never releases
  (`azp`, `jti`, `sid`, `nbf`, `cnf`, `scope`, `client_id`, `typ`, `c_hash`,
  `s_hash`, `_claim_names`, `_claim_sources`) and case variants of a
  protocol, standard or other entry's claim; its names become the only
  spelling released. `Request.Claims` only holds the claim requests the
  provider may release, and a grant records only those; the values of a
  voluntary `acr` request join `Request.ACRValues`, which now holds each
  value once. See [MIGRATION.md](MIGRATION.md).
- **OAuth2 requests and parameters are bounded (breaking)**: a query or
  body over `ServerConfig.MaxRequestBytes` (64 KiB by default) is refused
  with `invalid_request` (a bare 400 at `/authorize`) before it is parsed; a
  `nonce` over 512 bytes, not UTF-8 or holding NUL, and a `state` over 4096
  bytes or outside VSCHAR are refused with a redirected `invalid_request` —
  the state not echoed; a `client_id` over 255 bytes is an unknown client;
  the PKCE parameters of an implicit request, and a `code_challenge_method`
  without `code_challenge`, are ignored. See [MIGRATION.md](MIGRATION.md).
- **OAuth2 `/authorize` answers a POST with 303 (breaking for clients
  asserting 302)** and lists `Allow: GET, POST` on its 405. See
  [MIGRATION.md](MIGRATION.md).
- **OAuth2 registered redirect URIs are validated (breaking)**: one that
  `oauth2.ValidateRedirectURI` refuses — relative, with a fragment, a
  private-use scheme without a period such as `myapp:` or `javascript:`, a
  query naming a response parameter — is answered with a bare 400, never
  redirected to. See [MIGRATION.md](MIGRATION.md).
- **OAuth2 failed client authentications read alike**: every `401
  invalid_client` of `/token`, `/revoke` and `/introspect` carries the
  description "client authentication failed"; the reason ("unknown client",
  "method not allowed for client"…) moved to the cause `OnError` receives.
  See [MIGRATION.md](MIGRATION.md).
- **OAuth2 client-store failures are outages (breaking for stores reporting
  "not found" with an error)**: a `ClientStore` error not carrying
  `invalid_client` is answered as a failure — a bare 500 at `/authorize`,
  `server_error` at `/token` and `/introspect`, `temporarily_unavailable` at
  `/revoke` — and reported to `OnError`, instead of an unknown client. See
  [MIGRATION.md](MIGRATION.md).
- **OAuth2 `/introspect` and `/revoke` are bound to the issuer of the
  request (breaking for multi-issuer deployments)**: a token issued under
  another issuer introspects `{"active":false}` and is not revoked; without
  an `IntrospectionPolicy`, a refresh token is disclosed to its own client
  only; a token recorded without issuer is inactive at a non-empty issuer.
  Resource servers call `/introspect` at the issuer of the tokens they
  accept. See [MIGRATION.md](MIGRATION.md).

### Fixed

- `oidcclient.Client.StartLogin` capped the binding cookies at four by
  expiring the oldest cookies whose name started with the binding prefix —
  `oidc-` with `InsecureCookies`, `__Host-oidc-` otherwise — so it could
  delete the application's own `oidc-session`. Only names of the binding
  cookie's shape (the prefix and 16 lowercase hex digits) are now counted
  and expired.
- The `oidc/client` documentation said that, the JSON being parsed
  strictly, an application decoding claims itself never reads another
  member than the one validated. Only two names differing by case are
  refused: a lone `EMAIL_VERIFIED` is another claim, kept as OpenID Connect
  Core §2 requires, which `encoding/json` reads as `email_verified`. The
  documentation now says so and points to `DecodeClaims` /
  `UserInfo.Decode` and the `Identity` fields.
- The v0 authentication `Handler` no longer iterates past a successful
  authentication and no longer swallows provider errors — the `Manager`
  short-circuits on first success and aggregates failures.
- The OAuth2 client-secret mismatch is now a typed error
  (`ErrClientSecretMismatch`) instead of a silent failure.
- The OAuth2 `/token` response now computes `expires_in` from
  `ServerConfig.Now` instead of the wall clock, so an injected clock stays
  authoritative on the wire; the value is rounded to the nearest second (a
  1h TTL is advertised as `3600`, not `3599`) and an already-expired token
  drops the field rather than sending the negative lifetime RFC 6749 §5.1
  does not allow.
- A rotated OAuth2 refresh token keeps the scope of the token it replaces
  (RFC 6749 §6); narrowing the scope of a refresh only narrows the issued
  access token. The replacement used to inherit the narrowed scope, so the
  grant shrank permanently and a later request for the original scope was
  refused with `invalid_scope`.
- The SQL store's schema (`oauth2/store/sql`) runs on PostgreSQL and MySQL:
  the refresh-token `consumed` flag is a `SMALLINT` — PostgreSQL rejected
  the former `BOOLEAN NOT NULL DEFAULT 0` column and the store's integer
  comparisons — and the token-family indexes are gone, since MySQL rejects
  their `CREATE INDEX IF NOT EXISTS`. `Schema` returns the same DDL for
  every dialect.
- A failed family revocation after a refresh-token reuse the store detects
  is no longer swallowed: the SQL and Redis stores returned the bare
  `ErrRefreshTokenReused` whatever the revocation did. The error now also
  wraps `oauth2.ErrTokenFamilyRevocationFailed` and its cause; the
  `refresh_token` grant then retries the revocation and reports a second
  failure to `grant.Config.OnError`, while the client still gets
  `invalid_grant`. The revocations a reuse triggers now run on a context
  detached from the request, so a client hanging up cannot abort them.
- A failed exchange no longer leaves a live access token behind: the
  `authorization_code`, `refresh_token` and legacy `password` grants
  persisted the access token before minting the refresh token and rotating,
  so a later failure left an access token the client never received. Each
  exchange now persists its tokens in one atomic call.
- A refresh token that disappears between the grant's lookup and its
  rotation — e.g. expired from Redis — is answered `invalid_grant` (RFC 6749
  §5.2) instead of `server_error`.
- `/revoke` no longer answers `200 OK` for a revocation that may not have
  taken effect: when a token lookup fails for another reason than an
  unknown token, the token's family cannot be revoked, or a token outside
  any family cannot be deleted, it answers `503 temporarily_unavailable`
  (RFC 7009 §2.2.1), so the client knows to assume the token still exists
  and retry. An access token is revoked through its family first, and only
  then deleted, so the retry redoes the whole revocation. A failed lookup
  used to skip the revocation silently; every storage failure now reaches
  `ServerConfig.OnError` once, as a `server_error` with its cause. An
  unknown token, or another client's, still answers `200 OK`.
- `RevokeRefreshFamily("")` no longer deletes every access token outside a
  family (`client_credentials`, implicit) in the memory and SQL stores; it
  is rejected with `invalid_request`.
- A rotation whose replacement declares another family than the presented
  token's is refused with `invalid_request`; the Redis store used to revoke
  the declared family, not the stored one, on reuse.
- The `error_description` of `oauth2.ErrRefreshTokenReused` is now
  `refresh token reused`. The former `refresh token reused — family
  revoked` claimed a revocation that may have failed, and its em dash lies
  outside the RFC 6749 §5.2 `error_description` charset.
- `client_secret_basic` (`oauth2/clientauth`) form-decodes the client
  credentials as RFC 6749 §2.3.1 and Appendix B require: the Basic user-id and
  password are split at the first colon, then each is
  `application/x-www-form-urlencoded`-decoded, so a client identifier or
  secret holding reserved or non-ASCII characters — sent encoded, as
  `golang.org/x/oauth2` does — authenticates. Breaking for clients sending
  `%` or `+` unencoded (an unencoded `+` now reads as a space, an invalid
  escape is a malformed header); credentials made of unreserved characters
  are unaffected. The empty-credential guard applies to the decoded values.
  See [MIGRATION.md](MIGRATION.md).
- `make generate` works again: `.mockery.yaml` used mockery v3 syntax while
  the pinned tool was v2, and mockery needs a Go 1.27-aware `x/tools` to load
  the packages (v3.8.1).
- The OAuth2 token endpoint requires `redirect_uri` only when the
  authorization request included one (RFC 6749 §4.1.3): a client with a
  single registered redirect URI that omitted it at `/authorize` was refused
  at `/token` unless it sent the URI anyway. A `redirect_uri` sent at
  `/token` is still compared with the URI the code was delivered to.
- OAuth2 documentation matches the code: `HashToken` is an HMAC-SHA256 —
  with an empty key for the shipped token machinery — not a bare SHA-256;
  the token endpoint reads the parameters of an
  `application/x-www-form-urlencoded` body and does not check the content
  type; client grant types are compared exactly, not case-insensitively; and
  `Profile20BCP` refuses the legacy `password` grant as well as `implicit`.
- Contract violations no longer panic the request path: an authenticator or
  a custom `Manager` returning no authenticated value without an error, a
  nil `Attribute`, a nil `Authentication` passed to `Decide`, and a voter
  returning an undefined `Decision` now fail closed (an error, a denial, the
  anonymous authentication, a deny vote) — typed nils included. An
  extractor's typed nil is "no credential".
- A custom `Engine` returning a typed nil `Authentication` made
  `httpsec.Middleware` panic; it is now answered 500, like a nil one.
- `grpcsec` sends the metadata staged on its `Carrier` as the response
  header, refused RPCs included, as its documentation said; it was dropped.
  A custom `Engine` returning no authentication — nil or a typed nil — no
  longer panics the interceptors, which crashed the server: grpc-go
  recovers no panic.
- A ConnectRPC unary call refused with `Unauthenticated` (HTTP 401) carried
  no `WWW-Authenticate` field (RFC 9110 §11.6.1); it now carries the
  challenge. Headers staged on the `connectrpcsec.Carrier` reach the client
  on a refused call and on a handler error too, and a custom `Engine`
  returning no authentication — nil or a typed nil — no longer panics the
  interceptors.
- Documentation drift: `AttrPrincipalSubject` no longer references a
  non-existent `SetSubjectAttributeMode`, the HTTP middleware no longer
  promises a route override it could not offer, and `LIMITATIONS.md` lists
  the ConnectRPC adapter. `docs/security-considerations.md` documents the
  extractor order (first extractor wins) and its CSRF implication.
- `jwtsec.ErrAlgorithmNotAllowed` was never returned: go-jose refused a
  disallowed algorithm first and the error surfaced as
  `ErrMalformedToken`.
- The `jwtsec.NewRemoteJWKS` godoc promised a refresh on an unknown `kid`
  and deduplicated fetches, and `docs/security-considerations.md` said JWK
  Sets were fetched through `outbound`: none of it held (see Security).
- `now == exp` was accepted by the JWT verifier (RFC 7519 §4.1.4).

- The SAML Redis store answered `ErrTransactionExists` only when a second
  save differed from the stored transaction: an identical one succeeded. It
  now recognizes only a resend of the same call (its nonce).
- A SAML login's `AppState` came back altered from a SQL store whose column
  or connection character set could not represent it under a non-strict
  `sql_mode` (a latin1 MySQL replaced characters with `?`): the transaction
  payload is now ASCII-only JSON.
- `saml/sp/storetest` checks retention over time: a store forgetting a
  consumption or a replay mark shortly after recording it used to pass;
  records past their expiry may be purged, never altered.
- `xs:duration` values of exactly 2^63 nanoseconds are refused on every
  platform (they parsed as the minimum or maximum duration depending on the
  architecture).
- A SAML signature whose `KeyInfo` carries no certificate (a `KeyName` or a
  `KeyValue` only, which Core §5.4.5 allows) is verified like one without
  `KeyInfo` instead of failing.
- Unicode format and line/paragraph separator characters (bidirectional
  overrides, zero-width characters) are stripped from a SAML
  `StatusError.Message`.
- `oidcprovider.New` keeps its own copies of `Config.ACRValuesSupported`
  and `Config.ClaimsSupported`, taken before they are validated. It used to
  keep the caller's `ACRValuesSupported` slice: a later write by the caller
  reached the discovery document's `acr_values_supported` unvalidated, and
  raced its handler.
- `oidc/provider` treats an empty occurrence of a request parameter as
  omitted wherever it stands, as the oauth2 core does (RFC 6749 §3.1:
  "Parameters sent without a value MUST be treated as if they were omitted
  from the request"). An OpenID request carrying `nonce=&nonce=n-1` — an
  empty first occurrence of any parameter the core reads — was refused, with
  `invalid_request` or, for `client_id`, `redirect_uri` and
  `response_mode`, a bare `400`; it is now served like `nonce=n-1`. Two
  occurrences with a value are still refused.
- OAuth2 redirects keep the query of the registered redirect URI byte for
  byte (RFC 6749 §3.1.2: it "MUST be retained"): it was re-encoded —
  reordered, `;`-separated pairs dropped, `flag` turned into `flag=`. The
  implicit flow no longer appends a second fragment.
- OAuth2 accepts any port for a registered loopback IP redirect URI
  (`http://127.0.0.1`, `http://[::1]`), as RFC 8252 §7.3 requires for native
  apps: the request is otherwise matched exactly, and the code bound to the
  URI requested.
- OAuth2 storage failures stop hiding: a token lookup that failed at
  `/introspect` answered `{"active":false}` without reaching `OnError` (it
  still answers so — RFC 7662 §2.1 — and is now reported), and a failing
  `ClientStore` read as an unknown client — `invalid_client`, which tells a
  client its credentials are wrong — although the `ClientAuthenticator`
  contract asked to return store failures as such.

### Removed

- The legacy v0 packages: `authentication/`, `authentication/credential/`,
  `authentication/provider/{dao,oauth2}/`, `authorization/`, and the
  in-tree `password` package.
- `voter.FullyAuthenticated()`: it behaved exactly like
  `voter.Authenticated()` — no remember-me or authentication-strength concept
  exists to tell them apart — while promising a stronger check.

### Security

- **CI and release supply chain**:
  - the workflows run with a read-only `GITHUB_TOKEN` by default
    (`permissions: contents: read`); only the release `publish` job gets
    `contents: write`;
  - every action is pinned to a full commit SHA, which Dependabot keeps
    current;
  - checkouts no longer persist credentials;
  - the coverage goes to Coveralls through goveralls, built from its pinned
    module (`tools/goveralls`), instead of an action referenced as `@master`
    and handed the token, and a Coveralls outage no longer fails the build;
  - pushes to `master` are never cancelled by a later push, so every master
    commit keeps its CI result;
  - the release workflow is split: a read-only job verifies the tag
    (`scripts/release-check.sh`, build, test, lint, govulncheck on the
    released module), then a
    minimal job publishes with `gh release create`, without checkout or
    third-party action. The tag reaches the scripts through the environment,
    and tags of nested modules (`oidc/client/v…`) now trigger it;
  - a new `govulncheck` workflow scans every module on every change and
    weekly;
  - Dependabot also covers the tool modules and the actions, groups related
    updates, and waits 7 days before proposing a version.
- `grpc` (and the examples) require `golang.org/x/net` v0.60.0 instead of
  v0.58.0: HTTP/2 advisories GO-2026-6603, -6610, -6611, -6612 and -6617.
- The OAuth2 token endpoint refuses a `code_verifier` presented for an
  authorization code issued without `code_challenge` (RFC 9700 §2.1.1,
  §4.8.2, #86), under every profile. Under `Profile20` — where PKCE is
  optional — it used to ignore the verifier and issue tokens, so an
  attacker could strip `code_challenge` from its own authorization request
  and inject the resulting code into a victim's session at a client relying
  on PKCE instead of `state` (the PKCE downgrade attack).
- The integrity MAC of an `oidc/client` login transaction is keyed by a
  server-held transaction key as well as by the login's binding secret
  (#86). Keyed by the binding secret alone, it could be recomputed by an
  attacker with write access to the transaction store for a login it ran
  in its own browser — which holds that secret — to strip the login's
  `max_age` or `acr_values` requirement (a step-up or MFA bypass) or to
  rewrite its `AppState`. Such a transaction now fails with
  `ErrTransactionIntegrity` before the code is redeemed; the store is
  trusted for availability and single consumption only.
- An `oauth2.DefaultClient` printed with `fmt` or logged with `slog`
  revealed its cleartext secret; it now prints and logs its registration
  with the secret redacted, whatever the verb (#86).
- An `oidcclient.Client` printed with `fmt` revealed its client secret and
  transaction keys (fmt prints the unexported fields of a struct pointer),
  and `Config`, `AuthRequest`, `Callback`, `Identity` and `Tokens` revealed
  their secrets with the verbs their `String` method does not cover (`%d`,
  `%t`…). Every one now prints its redacted form with every verb
  (`fmt.Formatter`) and logs without secrets in `slog` (#86).
- An `oidc/client` `Client` whose `Config.Outbound.MaxRedirects` allowed
  redirects followed its discovery and JWK Set requests to any origin: a
  server at the end of a redirect from the issuer's well-known URL only had
  to write the configured issuer in its document to get its own endpoints
  and keys trusted, and its ID Tokens accepted (OpenID Connect Discovery 1.0
  §7.2 relies on TLS to the issuer), and a redirect of the `jwks_uri` made
  another origin's keys verify ID Tokens. Every hop of these requests must
  now stay on the origin — scheme, host and port — of the URL requested:
  the issuer's for discovery, the `jwks_uri`'s for the keys; another hop
  fails with `outbound.ErrRedirectNotAllowed`. Token and UserInfo requests
  still never follow redirects, and the default policy follows none.
- `encoding/json` wrote the binding secret of an `oidcclient.AuthRequest`
  and the binding secret, authorization code and state of a `Callback` —
  and so did `slog`'s JSON handler for one nested in another logged value,
  `LogValue` applying to attribute values only. Both now encode without
  them (`MarshalJSON`: the binding `REDACTED`, a callback's URL without its
  query and its parameters counted), and so does `Config` (client secret
  redacted, transaction keys counted), whose encoding used to fail on its
  `func` fields only by accident. `UserInfo` printed its claims (personal
  data) with `%s` and `%q`; it now prints and logs its subject only.
  `Identity` and `Tokens` still encode their tokens, deliberately, so that
  applications can persist them (see MIGRATION.md).
- `oidcclient.AuthOptions.ExtraParams` compared its names with the
  reserved parameters exactly: `Request`, `STATE`, `Nonce`, `request.uri`…
  passed, and a provider that ignores case (ASP.NET) or rewrites `.` as `_`
  (PHP) read them as the reserved parameter — a request object or a nonce
  the godoc promised to refuse. They also repeated the parameters of the
  authorization endpoint's own query (`?tenant=acme` then `tenant=evil`),
  which RFC 6749 §3.1 forbids. Names are now compared by a key folding case
  and reading `.`, space and `[` as `_`: `Begin` refuses an entry equivalent
  to a parameter the client sends or does not support, to one of the
  endpoint's query, or to another entry (`ErrInvalidAuthRequest`), and
  `New` refuses an authorization endpoint whose query does the same
  (`ErrInvalidMetadata`).
- `oidc/client` errors echoed provider-controlled text without bound: a
  900 KB issuer in a discovery document made a 900 KB error, and so did a
  media type, a redirect target (the `Location` of a refused redirect, which
  `net/http` puts in its error), a JOSE header member quoted by go-jose,
  the names of the authorization endpoint's query, or the debug data of an
  HTTP/2 GOAWAY interrupting a response body (64 KB); `%q` could also
  multiply hostile bytes by four. Every echoed value is now Go-quoted, then
  cut to about 256 bytes (beginning and end kept), invalid UTF-8 replaced;
  wrapped errors keep their chain (`errors.Is`/`errors.As`). Configuration
  and `AuthOptions` values echoed into errors are bounded the same way.
- `jwtsec` keys revealed their material: a `PrivateKey` holding an Ed25519
  or HMAC key — or an HMAC secret carried as a `PublicKey` — printed it with
  `fmt` (`%v` and most verbs), as did a `Signer` or a `NewStaticJWKS` key
  set holding one (fmt prints the unexported fields of a struct pointer),
  and `encoding/json` — so `slog`'s JSON handler — wrote the material of
  every private key. Keys, signers, key sets, verifiers and
  `OAuth2AccessTokenSigner` now print, log and encode their key IDs,
  algorithms and key types only, whatever the verb; an asymmetric
  `PublicKey` still encodes as before (#86).
- A `session.Codec` printed with a `fmt` verb a pointer does not take
  (`%s`, `%q`…) revealed the AES-256 key schedule of its ciphers, which
  starts with the encryption key; it now prints `session.Codec{Keys: n}`
  whatever the verb (#86).
- Multi-issuer deployments can keep each client in its realm: with the
  `oauth2.IssuerBoundClient` capability (see Added), a client of one issuer
  can no longer send another issuer's end-users to that issuer's login page
  and obtain their codes, tokens and ID Tokens, nor be told apart from an
  unknown client there. Clients without the capability keep being known at
  every issuer of a shared `ClientStore`.
- Authorization responses name their issuer (RFC 9207, see Added): a client
  of several authorization servers or realms can detect a mix-up attack
  (RFC 9700 §4.4).
- RFC 9068 access tokens are typed `at+jwt` (see Changed), so a verifier
  requiring that type never accepts an OpenID Connect ID Token signed by the
  same keys as an access token (RFC 8725 §3.11).
- The OpenID Provider (see Added) enforces the protocol itself rather than
  trusting the application: `prompt=login`, `max_age` and essential `acr`
  are re-checked on every approval, an authentication counts in its realm
  only, `prompt=none` refusals read the same whatever sessions the browser
  holds, private and symmetric keys are never published, an access-token
  audience equal to a client ID is refused (RFC 9068 §5), and UserInfo only
  serves tokens of clients still registered at the issuer.
- The SAML 2.0 Service Provider (`saml/sp`) trusts only the IdP entity ID
  and the signing certificates of each connection, and refuses before any
  signature work what parsers could read differently: DTDs, several
  assertions, misplaced or repeated signatures, two attributes of one local
  name, SHA-1 (unless a connection opts in), inclusive C14N and unknown
  algorithms, encrypted assertions, and documents over the size, element,
  depth and namespace limits — including SAMLResponse values of a form the
  application parsed first. Every identity value comes from the verified
  canonical bytes; responses are bound to the browser, the connection and
  the request, and consumed once. It requires
  `github.com/russellhaering/goxmldsig` v1.6.1 or later (CVE-2026-33487,
  GHSA-qhrp-hfff-vphr) and gosaml2 v0.12.0 or later (GHSA-66r8-42f7-4q74).
  See [docs/security-considerations.md](docs/security-considerations.md#saml-service-provider).
- The SAML Service Provider's lexical gate also refuses XML names that are
  not namespace-well-formed (Namespaces in XML 1.0 §3 and §7): an element
  or attribute name with an empty prefix or an empty local part (`<:x>`,
  `p:=""`, `xmlns:=""`), which encoding/xml keeps whole, colon included, in
  no namespace. No reader disagreed on them yet; they are refused, like the
  other names readers could read differently (`ErrMalformedResponse`).
- SAML login transactions carry a MAC under a server-held key
  (`samlsp.Config.TransactionKeys`, required), verified in constant time
  before any stored field is used. Whoever could write to the transaction
  store could rebind a pending login to her own browser — completing it with
  a victim's captured response — or drop its `ForceAuthn` and
  `RequestedAuthnContext` requirements; such a record now fails with
  `ErrTransactionIntegrity`, and the stores are trusted for availability and
  single consumption only. The transaction is consumed with the digest of
  the cookie the browser presented, never the stored one.
- A SAML login allows one signature verification. `CompleteLogin` consumes
  the transaction after the browser binding, transaction, status and
  `InResponseTo` checks and before any signature work: one `BeginLogin` no
  longer buys unlimited verifications — up to three gosaml2 runs each when a
  signature has no `KeyInfo` — sequential or concurrent, and a refused
  response ends the login. For signatures without `KeyInfo`, the certificate
  that verified the connection's last such signature is tried first.
- `samlsp.Connection.ResponseOrigins` (opt-in) refuses a response posted to
  the ACS from another origin than the IdP's pages (`ErrOriginMismatch`),
  closing the login CSRF a leaked in-flight IdP redirect URL allowed: the
  IdP's response to the victim's request, obtained for the attacker's
  account and auto-posted from the attacker's page, signed the victim in as
  the attacker.
- The SAML ACS checks where a response was received (Core §3.2.2,
  Bindings §3.5.5.2): the request's escaped path, its host (`r.Host`) and
  the absence of a query string must be the connection's ACS URL's. A
  Success `Response` must carry `InResponseTo`, equal to the request ID.
- Parser differentials refused before any signature work: `xml:`
  attributes other than `xml:lang`, `xml:space`, `xml:base` and `xml:id`
  (`xml:NotBefore`, `xml:Destination` were read by encoding/xml as the SAML
  attributes, unchecked by the pre-check), DTDs and processing instructions
  in the parsed tree as well as in the token stream, and a status code that
  is Success only once white space is stripped.
- The SAML replay cache is keyed by connection: a tenant whose IdP reuses
  another IdP's entity ID can no longer burn the assertion IDs of the other
  tenant's connection.
- A `samlsp.Config` or `*samlsp.ServiceProvider` printed with `fmt` (any
  verb) or logged with `slog` no longer reveals the signing key or the
  transaction keys.
- The HTTP `DefaultErrorMapper` no longer reflects the wrapped error chain
  into the `WWW-Authenticate` header. The RFC 6750 `error_description` is now
  a fixed, generic string per error code, so internal context (timestamps,
  package and authenticator names, consumer-supplied `TokenVerifier`/store
  errors) can no longer leak to clients.
- The OAuth2 `refresh_token` grant now enforces the refresh-token rotation
  that `Profile20BCP` (the default) and `Profile21Draft` mandate (RFC 9700
  §4.14.2) — for every client, stricter than RFC 9700 §2.2.2, which only
  requires it (or sender-constrained refresh tokens) for public clients —
  whatever `grant.Config.RotateRefreshTokens` says: every exchange consumes
  the presented refresh token and returns a new one, and replaying a
  consumed token is refused with `invalid_grant` and revokes the whole
  family. The zero configuration used to let the same refresh token be
  replayed until it expired. Clients MUST keep the refresh token returned
  by each exchange (RFC 6749 §6). A grant that has to rotate but has no
  `grant.Config.RefreshTokens` generator — including under `Profile20`
  with `RotateRefreshTokens` set, which used to skip the rotation
  silently — is refused by `oauth2.NewServer`, and should it run anyway
  (called directly, or behind a decorator that hides it from `NewServer`)
  it fails with `server_error` before any token is minted or persisted.
  Non-rotating refresh tokens remain an explicit `Profile20` choice
  (`RotateRefreshTokens: false`).
- OAuth2 token-family revocation is race-free and authoritative in every
  store (RFC 9700 §4.14.2, RFC 7009 §2.1). Once `RevokeRefreshFamily`
  returns — or a reuse is reported without
  `ErrTokenFamilyRevocationFailed` — no token of the family is usable
  through the store, and no issuance or rotation into the family succeeds,
  including one racing the revocation. Before, a rotation or a non-rotating
  `Profile20` refresh could leave a usable token in a family whose
  revocation had just completed: the SQL statements ran outside a shared
  transaction, the Redis revocation enumerated the family non-atomically,
  and nothing gated issuance. A revocation also left no trace for a family
  without tokens yet. A Redis rotation resent by go-redis after a lost
  reply is no longer mistaken for a reuse that revokes the family it just
  rotated into. JWT access tokens verified offline stay out of the store's
  reach until they expire: see
  [docs/security-considerations.md](docs/security-considerations.md).
- The OAuth2 `/introspect` endpoint now answers only clients whose
  `Type()` is `oauth2.ClientConfidential` (RFC 7662 §2.1 / §4, RFC 6749
  §2.2, §2.3). It used to answer any client the shared `ClientAuth` chain
  authenticated, so anyone knowing a public `client_id` — which is not a
  secret — could read the validity and claims of any token they held,
  refresh tokens included: through the `none` method, or through
  `client_secret_basic` / `client_secret_post` with the client's registered
  secret (Basic: even an empty one), whether or not `none` was registered.
  Public clients, whatever the method, and untyped clients (`Type() == ""`)
  authenticated through Basic or Post — `none` already refused them — now
  get `401 invalid_client`. This breaks deployments whose applications, or
  resource servers registered without a type, call `/introspect`. `/token`
  and `/revoke` are unchanged. The `none` method's `error_description` for
  a non-public client no longer contains a double quote, which RFC 6749
  §5.2 forbids. See [MIGRATION.md](MIGRATION.md).
- The OAuth2 server now enforces the RFC 7636 PKCE syntax, not just the
  transformation. `/authorize` answers `invalid_request` to a
  `code_challenge` that is not 43–128 unreserved characters (`plain`) or
  not the unpadded base64url SHA-256 digest (`S256`); for a code bound to a
  `code_challenge`, `/token` answers `invalid_grant` to a `code_verifier`
  that is not 43–128 characters of `A-Z a-z 0-9 - . _ ~`, and the code
  stays consumed — a one-character verifier whose S256 challenge matched
  used to be exchanged for tokens.
  `pkce.Verify`/`VerifyS256` return false for a malformed verifier, and
  `pkce.ValidVerifier`/`pkce.ValidChallenge` expose the checks. Missing or
  unsupported methods and the profile ban on `plain` keep their error
  codes; their `error_description` no longer contains a double quote,
  which RFC 6749 §4.1.2.1 and §5.2 forbid, and no longer echoes an
  unsupported `code_challenge_method`.
- A replayed OAuth2 authorization code now revokes every token issued from
  it — access and refresh tokens, and every later rotation — in every store
  (RFC 6749 §4.1.2, §10.5; RFC 9700 §4.2.4). The `authorization_code` grant
  derives the token family from the code before consuming it, so a replay
  racing the first exchange cannot leave its tokens active: one landing
  before that exchange persists its tokens makes it fail with
  `invalid_grant` — as long as the store keeps the revoked family record
  (see the deployment requirements in
  [docs/security-considerations.md](docs/security-considerations.md)) — and
  one landing after revokes them. Only a replay that would itself have been
  accepted revokes: the code has not expired, and the client it was issued
  to presents it with the same `redirect_uri` and PKCE verifier and may
  still use `authorization_code` (OAuth 2.1 §4.1.3, §7.5.3). A public
  `client_id` is no secret, so unknown codes, other clients and missing or
  wrong verifiers revoke nothing. The replay is still refused with
  `invalid_grant`, and a failed revocation is reported through
  `grant.Config.OnError`. JWT access tokens validated offline stay valid
  until they expire. Previously the tokens issued from a replayed code
  stayed valid.
- OAuth2 `client_secret_basic` no longer authenticates a client with an
  empty password (RFC 6749 §2.3, §10.1). It handed the empty secret of
  `Authorization: Basic base64("<client_id>:")` to the client's
  `SecretMatcher`, and `DefaultClient.SecretMatches` matched it against an
  empty `Secret`: anyone knowing the `client_id` of a client registered
  without a secret authenticated as it at `/token` — obtaining tokens,
  `client_credentials` included — and at `/revoke`, whatever the client's
  type, and at `/introspect` when the client was confidential, reading the
  validity and claims of the tokens they held. `client_secret_basic` now
  answers a missing `client_id` or an empty password with
  `401 invalid_client` (`missing client_id or client_secret`) before
  loading the client, with the guard `client_secret_post`'s `Authenticate`
  already has: no store lookup, one answer for every client.
  `DefaultClient.SecretMatches` never matches an empty `Secret`, and the
  `oauth2.SecretMatcher` contract now says implementations MUST NOT match
  an empty secret: callers of `DefaultClient` are covered, custom matchers
  are told to follow suit. Public clients still authenticate with `none`,
  by design — they cannot use `client_credentials`, which only confidential
  clients may (RFC 6749 §4.4). This breaks public
  clients that sent an empty Basic password — they must use `none` — and
  clients registered as confidential or untyped that authenticated with an
  empty Basic password. See [MIGRATION.md](MIGRATION.md).
- OAuth2 authorization codes and refresh tokens are bound to the issuer they
  were issued under (OIDC Core §16.15). In a deployment whose
  `IssuerResolver` serves several realms, a client could redeem a code
  authorized at one issuer, or refresh a token issued there, at another one
  — obtaining tokens, and with an OpenID provider ID Tokens, of realm B for a
  subject of realm A. Both are now refused with `invalid_grant`; a refused
  refresh consumes nothing, and a code replayed at another issuer revokes
  nothing (it could not have redeemed the code). Codes and refresh tokens
  written before the upgrade carry no issuer and are refused — users
  re-authenticate — unless the SQL backfill of [MIGRATION.md](MIGRATION.md)
  applies.
- OAuth2 `/authorize` refuses a `response_mode` it cannot honor — anything
  but the response type's default, `query` for the code flow or `fragment`
  for an enabled implicit flow — with a bare `400` that is never redirected
  (OAuth 2.0 Multiple Response Type Encoding Practices §2.1; OIDC Core 1.0
  incorporating errata set 2, §3.1.2.6), before any other check that would
  redirect. It used to ignore the parameter and answer, code included, in a
  mode the client had not asked for. This breaks clients sending an
  unsupported `response_mode` such as `form_post`. The RFC 8414 metadata now
  publishes `response_modes_supported: ["query"]` — its omission meant
  `["query", "fragment"]` (RFC 8414 §2).
- OAuth2 error responses keep to the RFC 6749 §4.1.2.1 / §5.2 syntax: a
  malformed error code from a grant, an extension or a `Consent.Refusal` is
  answered `server_error` (the original reaching `OnError`), a description or
  `error_uri` outside the charset is left out, and `/authorize` redirects only
  the error codes the authorization endpoint defines. A nil `*oauth2.Error`
  returned by a callback or a grant is answered `server_error` instead of
  panicking (`Error`, `Unwrap` and `IsCode` tolerate a nil receiver). The
  `invalid_scope` and
  `unsupported_response_type` descriptions no longer quote or echo the
  request: the former put a double quote, outside the charset, in every
  `invalid_scope` redirect.
- OAuth2 scope handling is linear and bounded: comparing a requested scope
  with a client's registration, or a consent's or an extension's narrowing
  with the request, took time proportional to the product of their sizes, and
  no request bounded them — tens of thousands of unique scope tokens in one
  `/authorize` URL cost seconds of CPU. Scope values are now parsed once,
  refused beyond 100 tokens or 4096 bytes, and compared with set lookups.
- The OAuth2 consent step can no longer broaden a request without scope. A
  non-empty `Consent.Scope` had to be a subset of the requested scope, but an
  empty request admitted any scope — even scopes the client is not registered
  for — so a `ConsentFunc` taking `Consent.Scope` from request-influenced
  input (the checkboxes of a consent form) could grant `admin` to a client
  allowed `read`. A consent now only narrows the request (RFC 6749 §3.3), and
  a blank one (spaces only) grants exactly what was requested.
- The OAuth2 `client_credentials` grant refuses every client that is not
  confidential with `unauthorized_client` (RFC 6749 §4.4: it "MUST only be
  used by confidential clients"). A public client authenticates with `none`
  — its `client_id` alone, public by definition (shipped in every copy of a
  browser or mobile app) — so anyone knowing it obtained access tokens whose
  subject is the client, with any scope when the client registered none.
  Untyped clients are refused too: the server cannot know they keep a
  secret.
- OAuth2 client registrations fail closed: a client registered without
  `GrantTypeValues` could use every grant — `client_credentials` and the
  legacy `password` grant included — and one without `ScopeValues` could
  request any scope, `admin` included. Both now allow nothing. The token
  endpoint checks the client's grant types for every grant before it runs,
  so a custom grant can no longer forget the check, and a code presented by
  a client not allowed `authorization_code` is no longer consumed.
- A refresh no longer outlives a client's scope registration: the
  `refresh_token` grant checked the requested scope against the original
  grant only, so a refresh token minted with a scope the client was not, or
  is no longer, registered for — through an empty `ScopeValues`, the
  consent broadening fixed above, or before an operator removed a scope from
  a compromised client — kept minting access tokens with it. A refresh now
  issues an access token only within the client's current `Scopes()`
  (`invalid_scope` otherwise, nothing consumed).
- OAuth2 `/authorize` checks the client's grant types: a client declaring
  neither `authorization_code` nor `implicit` obtained codes — refused only
  at `/token` — and, under `Profile20` with the implicit flow enabled, access
  tokens straight from the authorization endpoint. `response_type=code` now
  needs `authorization_code`, and `token` needs `implicit` (RFC 7591 §2.1);
  otherwise the request is answered `unauthorized_client` (RFC 6749
  §4.1.2.1, §4.2.2.1) before the extension or the `ConsentFunc` runs.
- OAuth2 public clients must use PKCE under every profile (RFC 9700
  §2.1.1), `Profile20` included: a public — or untyped — client obtained and
  redeemed codes without any PKCE under `Profile20`, although the
  documentation said public clients MUST use it. `/authorize` now answers
  `invalid_request` without `code_challenge` (RFC 7636 §4.4.1), and `/token`
  refuses such a client a code issued without challenge.
- The refresh tokens of OAuth2 public clients rotate under every profile
  (RFC 9700 §4.14.2: "Authorization servers MUST utilize one of these
  methods to detect refresh token replay by malicious actors for public
  clients" — sender-constrained tokens or rotation). Under `Profile20`
  without `RotateRefreshTokens`, a public — or untyped — client's refresh
  token stayed reusable until it expired, so a stolen one could be replayed
  undetected. Confidential clients keep the opt-in.
- OAuth2 endpoints refuse repeated request parameters (RFC 6749 §3.1,
  §3.2: they "MUST NOT be included more than once"). `/authorize`, `/token`,
  `/revoke` and `/introspect` used the first value of a repeated parameter —
  a `redirect_uri`, a `code`, a `client_id`… — while callbacks and other
  components could read another. A repeated `client_id`, `redirect_uri` or
  `response_mode` at `/authorize` is now a bare `400`, any other repeated
  parameter the server reads an `invalid_request`; an empty occurrence is
  omitted and never hides the value that follows. The `unsupported_grant_type`
  description no longer echoes the request. See [MIGRATION.md](MIGRATION.md).
- OAuth2 client authentication accepts one method per request (RFC 6749
  §2.3). A request carrying a valid HTTP Basic header and a wrong
  `client_secret` in its body was authenticated by the header — the body
  secret ignored — and one authenticated with Basic as client A naming
  `client_id=B` in its body was served as A. Both, and several
  `Authorization` fields, are now `invalid_request` (RFC 6749 §5.2) at
  `/token`, `/revoke` and `/introspect`.
- After a failed authentication the `Engine` stored the extracted
  `Authentication` — a cleartext password, a bearer token — in the request
  context; it now stores the anonymous authentication.
- The core spans carried the full error chain of the authenticators —
  including the username typed at a Basic prompt (a password typed in the
  username field) and wrapped store errors — as status description and
  exception event; they now carry the error class only, and
  `basic.Authenticator` no longer puts the typed username in its errors.
- `Authorities()` of the `basic`, `bearer` and `session` authentications
  returned their internal slice: a caller could rewrite the authorities of
  an authenticated value (`ROLE_USER` → `ROLE_ADMIN`). They now return a
  copy, and the `security.Authentication` contract requires it.
- The stock voters ignored the value of the attribute they were asked to
  check, and `voter.Authenticated()` / `voter.Anonymous()` voted on every
  attribute: a decision manager shared by several routes granted an ADMIN
  route to a USER, and `Authenticated()` next to a role voter granted any
  route to any logged-in principal. Voters now compare attribute values,
  and the authentication-state voters need their own attributes.
- `voter.Not()` turned the refusal of an unauthenticated principal into a
  grant (`Not(HasRole("BANNED"))` admitted anonymous callers); it no longer
  does.
- `NewUnanimousDecisionManager` with `WithAbstainFallback(DecisionGrant)`
  granted a decision without attributes — a route whose attribute lookup
  returned nothing — and any decision of a manager without voters, to anyone,
  anonymous callers included. Such decisions are now denied whatever the
  strategy, tie-break and fallback.
- `httpsec.Carrier` answered `Get`/`Values` from a cookie or from the query
  string when the header was absent: Basic and Bearer credentials were
  accepted from `?Authorization=…` and from a cookie named `Authorization`
  (leaking through logs, `Referer` and history), and a session from
  `?session=…` or from a `Session` request header — which even took
  precedence over the victim's cookie — so a link or a cross-site form
  logged the victim into the attacker's session. Credentials are now read
  from header fields only, and the session from its cookie only.
- The `httpsec.Middleware` span recorded the raw request path as
  `http.route` — reset tokens and e-mail addresses in paths reached the
  trace backend — and the raw method; they are now a route template (or
  absent) and a known method (or `_OTHER`).
- A request with several `Authorization` fields was authenticated with the
  first one; it is now refused (400), whatever the transport.
- The gRPC error messages told the client why authentication failed
  (`token expired`, `token not found`); they are now one fixed string per
  code. `grpcsec.Carrier` printed its incoming metadata — the bearer token
  in `authorization` — with `%v`; it now prints and logs key counts only,
  whatever the verb.
- `connectrpcsec.Carrier` printed its incoming headers — the bearer token
  in `Authorization` — with `%v`, and the Connect error messages told the
  client why authentication failed; the carrier now prints and logs key
  counts only, and the messages are one fixed string per code.
- The `grpc-bearer` example and the `grpcsec` godoc example installed only
  unary interceptors: the streaming `Health.Watch` RPC was served to callers
  without any token. Both now install the unary and stream chains through
  `grpcsec.ServerOptions` / `grpcsec.AuthorizeServerOptions`.
- **JWT claim smuggling** (`jwtsec`): claims were decoded with
  `encoding/json`, which matches member names case-insensitively and keeps
  the last duplicate, so a signed `"Sub"`, `"SCOPE"`, `"EXP"`, `"AUD"` or
  `"ſub"` overrode the registered claim. Claims are now decoded
  case-sensitively; duplicate and case-variant names, invalid UTF-8,
  unpaired surrogates, non-object payloads and mistyped registered claims
  (`"nbf": null`) are refused (RFC 7519 §4, §7.3, §10.1.1).
- **JWT parsing cost** (`jwtsec`): tokens of any length reached go-jose,
  which allocated about 100 times a hostile header's size (≈ 1 GiB per
  request on gRPC defaults); token values were echoed unbounded in errors
  and spans. Tokens over 16 KiB are refused before decoding; only the
  canonical compact serialization with a strict header is accepted
  (`crit`, `b64` refused, RFC 7515 §4.1.11, RFC 7797 §7).
- **Remote JWK Sets** (`jwtsec.NewRemoteJWKS`) were fetched outside the
  `outbound` SSRF guard — any destination, environment proxies, redirects
  including https→http whose keys were then trusted — under a lock held
  across the fetch, re-fetched on every call while failing, trusted forever
  when stale, never refreshed on an unknown `kid`, and not validated (`oct`
  keys used as HMAC secrets, RSA-1024, private keys). They are now fetched
  through `outbound` — a redirect, when the policy allows one, never leaves
  the JWK Set URL's origin — one fetch at a time, refreshed in the
  background and on unknown `kid`s (rate-limited, backed off), dropped
  after 24 h without a successful fetch, and validated key by key; an
  outage is `ErrKeySetUnavailable`, a `security.ErrUnavailable` the
  transports answer with 503 / Unavailable, never an invalid token (401).
- **JWT resource servers** (`jwtsec.BearerVerifier`) accepted any `typ`,
  `iss` and `aud` — an ID Token or another API's access token was accepted
  — and an empty `sub`: RFC 9068 §4 checks are now required.
- **Key ↔ algorithm binding** (`jwtsec.Verifier`): a key verified every
  algorithm of its family and a key without `Algorithm` any algorithm;
  static RSA-1024 and private keys verified tokens (RFC 8725 §3.1, RFC 7518
  §3.3).
- **Immortal tokens** (`jwtsec`): a year-1 `exp` (the zero `time.Time`,
  which the package's own signers emitted) disabled expiry; out-of-range
  dates wrapped around; the clock skew was unbounded.
- **Signing** (`jwtsec`): `NewSigner` signed with RSA-1024 and other unfit
  keys, and the RFC 9068 signer emitted empty `aud`, `iss`, `sub` or
  `client_id`.
- **Key material and URLs in output** (`jwtsec`): `PublicKey` JSON wrote an
  HMAC secret held as a `jose.JSONWebKey` and private keys carried by
  mistake; the remote JWKS provider and its errors printed the URL with its
  user name and query.
- `oidc/provider` parses `prompt`, `ui_locales`, `claims_locales` and
  `acr_values` without allocating per separator: splitting them first made
  an unauthenticated authorization request allocate about 20 times its
  body (16 bytes per space, before the 32-value cap). `prompt` is still
  read whole — bounding it could turn `none … login` into a valid `none` —
  while `ui_locales`, `claims_locales` and `acr_values` over 2048 bytes are
  now ignored, like an oversized `display` or `login_hint`; they never fail
  a request (OIDC Core §3.1.2.1, §15.1).
- `oidc/provider` no longer releases claim names that relying parties read
  as other claims. Its protocol-claim protection compared names byte for
  byte: an end-user whose attribute names she chooses could request, in her
  own authorization request, an attribute named `"ſub"` (U+017F) or
  `"SUB"`; it was released next to the genuine `sub`, and relying parties
  matching names case-insensitively — Go's `encoding/json`, so go-oidc, last
  member winning — read the victim's subject from her ID Token and UserInfo
  response (account takeover). Names are now compared ignoring case (simple
  and full case mappings), the diacritics lodash's `camelCase` strips from
  Latin letters, and every character but letters, decimal digits and `#`:
  case variants of protocol claims are never asked for nor released, known
  claims (standard claims, `roles`, `groups`, `entitlements`,
  `Config.ClaimsSupported`) only under their exact spelling, names that are
  case variants of one another never, nor invalid names or values whose
  member names alias at any depth (OIDC Core §2, §5.3.2; RFC 7519 §4). See
  [MIGRATION.md](MIGRATION.md).
- `oidc/provider` drops `offline_access` from every grant its
  `Decision` does not grant it to — plain OAuth 2.0 requests included,
  which the OIDC Core §11 rules used to skip: an approval meant for
  something else (a consent remembered per client, a page that never
  offered the choice) handed out a refresh token with
  `RefreshTokenScope = offline_access`, even right after the end-user
  declined offline access. `Request.OfflineAccess` is now set for every
  request; `OfflineAccessPrompted` needs no `prompt=consent` for a plain
  request, `OfflineAccessByPolicy` keeps the former behaviour, an implicit
  request never keeps it (Core §11), and an approval left without any
  scope answers `access_denied` (breaking, see
  [MIGRATION.md](MIGRATION.md)).
- `examples/oidc-provider` grants offline access only on the end-user's
  explicit choice — the consent page offers it to every request that can
  get it, plain OAuth 2.0 ones included, and never from a remembered
  consent — and remembers a consent for the scopes and claims the end-user
  saw: a consent given once to a client silently approved any later
  request of that client, new claims included. A consent answer applies to
  the very request its page showed — no longer to another one sharing its
  `client_id`, `state`, `nonce` and `code_challenge` — and to the end-user
  who gave it: another end-user signing in in the same browser before the
  request resumes is asked again.
- `examples/oidc-provider` bounds the logins in progress it remembers (at
  most 10,000; unused for 15 minutes, they expire and are purged): every
  authorization request of a browser without a session used to leave an
  entry for the life of the process. It compares the password of an
  unknown username with a dummy hash — the response time told whether an
  account existed — and its HTTP server sets read, write and idle timeouts.
- The in-memory OAuth2 store (`oauth2/storage/memory`) keeps tokens hashed
  only. It kept the raw access and refresh tokens it was handed — and
  returned them from `LookupAccessToken` and `LookupRefreshToken` — contrary
  to the storage contract ("MUST store hashes"); codes were already stored
  without their raw value. The `oauth2/storetest` conformance suite now
  checks that no lookup returns a raw token and that a store leaves the
  caller's pair untouched: a custom store keeping raw tokens fails it.
- OAuth2 requests can no longer make the server parse, echo or persist
  megabytes. Every endpoint read up to 10 MB of form; `/authorize` echoed any
  `state` in its redirects and recorded any `nonce` with the code — persisted
  by every store, re-encoded by the Redis consume script (tens of
  milliseconds of a blocked server per redemption, about 100 such codes
  filling 1 GB of a `noeviction` Redis, whose writes — revocations included
  — then fail). `oidc/provider` bounded the nonce of OpenID requests only.
  Requests are now bounded to 64 KiB, and the state and the nonce of every
  authorization request to 4096 and 512 bytes.
- OAuth2 `/authorize` responses can no longer be framed, cached or leak
  their URL in `Referer`. The endpoint set no header while the
  `ConsentFunc` rendered the login and consent pages behind it, and the
  canonical example approved any POST carrying `decision=approve` — a
  cross-site form could approve on the user's behalf. Every response now
  carries `X-Frame-Options: DENY`, `Content-Security-Policy:
  frame-ancestors 'none'`, `Cache-Control: no-store` and `Referrer-Policy:
  same-origin` (RFC 6749 §10.13, RFC 9700 §4.16, §4.2.4); the `ConsentFunc`
  godoc states the CSRF contract (RFC 6749 §10.12), and `examples/oauth2`
  refuses a cross-origin decision. A redirect answering a POST is a 303
  (RFC 9700 §4.12).
- OAuth2 no longer redirects to registered redirect URIs that cannot be
  safe ones: a relative URI, one with a fragment, a `javascript:` or `data:`
  URI, or a query naming a response parameter (which then traveled twice)
  were used as registered.
- OAuth2 `/authorize` can stop redirecting to clients it does not trust
  before the resource owner authenticated (RFC 9700 §4.11.2: the
  authorization server "MUST always authenticate the user first"). Any
  registered client could send users an erroneous or `prompt=none` request
  and have the server redirect them — without any authentication — to its
  redirect URI: `AuthorizeConfig.TrustedRedirect` answers such requests of
  untrusted clients with a bare error page.
- OAuth2 client authentication no longer enumerates clients: the
  `invalid_client` descriptions told an unknown client ("unknown client")
  from a known one with a wrong secret, and disclosed a client's type and
  methods ("none method reserved to public clients", "method not allowed
  for client"). Every failed client authentication now reads "client
  authentication failed" (RFC 6749 §5.2); the detail goes to `OnError`.
- OAuth2 realms no longer leak through `/introspect` and `/revoke`: behind
  an `IssuerResolver` serving several issuers, a client registered in two
  realms could introspect — and revoke — the tokens of one at the other,
  while the grants refused them there (OIDC Core §16.15). And without an
  `IntrospectionPolicy`, any confidential client — every resource server —
  could read the claims of any client's refresh token (RFC 6749 §1.5).
