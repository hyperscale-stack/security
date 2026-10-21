# Known limitations

The library covers HTTP, gRPC and ConnectRPC transports, HTTP Basic / Bearer
schemes, password hashing, JWT, OAuth2 (issuer + resource server), OpenID
Connect (provider and relying party), a SAML 2.0 Service Provider, production
storage backends, and stateless cookie sessions. This document tracks what is
**not** yet covered. Remaining items are tracked as GitHub issues rather than
future refactor phases.

## OAuth2 server

- **`private_key_jwt` client authentication (RFC 7523)** — not implemented.
  `client_secret_basic`, `client_secret_post`, and `none` are.
- **No throttling of client authentication** — `/token`, `/revoke` and
  `/introspect` verify a client secret on every request without limiting
  attempts: RFC 6749 §2.3.1 asks for brute-force protection, which a rate
  limiter in front of the handlers provides (per `client_id` and source
  address). Failures reach `OnError`.
- **No hashed-secret client** — `DefaultClient` keeps its secret in
  cleartext (compared by SHA-256 digest in constant time); keeping only a
  hash at rest takes a `Client` implementing `SecretMatcher` over your
  store — see [docs/security-considerations.md](docs/security-considerations.md).
- **Another client's token is "revoked" with 200** — `/revoke` leaves a
  token issued to another client, or under another issuer, untouched and
  answers it as an invalid token (RFC 7009 §2.2) where RFC 7009 §2.1 refuses
  the request with an error: a deliberate deviation, so that the answer
  never confirms the token is valid for someone else.
- **A failed introspection lookup answers inactive** — when the store fails
  to look a token up, `/introspect` answers `{"active":false}` (RFC 7662
  §2.1) and reports the failure to `OnError`: the resource server cannot
  tell an outage from a revoked token, and refuses the request either way.
- **`/.well-known/jwks.json` endpoint** — the `oauth2` module alone serves
  none, so its RFC 8414 metadata advertises `jwks_uri` (the issuer followed
  by `/.well-known/jwks.json`) only with `ServerConfig.AdvertiseJWKSURI`:
  mount the `oidc/provider` `JWKSHandler` (`oidcprovider.New` sets the flag),
  which serves the issuer's public keys, or publish your own with
  `jwtsec.MarshalJWKS` (it refuses private and symmetric keys) and set it.
- **Client and user subjects share `sub`** — a `client_credentials`
  token's `sub` is its client ID (RFC 9068 §2.2): a resource server tells
  it from a resource owner's token with
  `jwtsec.AccessTokenPrincipal.SubjectIsClient()` (JWT) or
  `AccessToken.ClientID == AccessToken.Subject` (store lookup), which also
  holds for a user whose subject equals the ID of the client they use, and
  never for a token without `client_id` (an issuer omitting it leaves
  disjoint identifiers as the only defence). Use it to refuse, and keep
  client IDs out of the user-subject namespace when clients can influence
  them (RFC 9700 §4.15.1).
- **Offline JWT access tokens are not revocable** — a token-family
  revocation takes effect in the store, not at resource servers verifying
  JWT access tokens offline (`jwtsec.BearerVerifier`): such a token stays
  valid until it expires, unless the resource server asks the
  authorization server with `jwtsec.WithActiveTokenCheck` (a lookup in a
  shared store, or RFC 7662 introspection — a request per token). Keep
  their lifetime short. See
  [docs/security-considerations.md](docs/security-considerations.md#offline-jwt-access-tokens).
- **Redis Cluster** — not supported by `oauth2/store/redis`: its Lua
  scripts touch keys of several hash slots (a token, its family, its
  replacement), and lookups by token hash cannot place them in one slot.
  Use a standalone server or a Sentinel primary: `New` refuses a Cluster or
  Ring client, and `Store.CheckDeployment` a server in cluster mode; a
  proxy sharding keys behind one endpoint is not detected and fails
  closed at runtime.
- **SQL expired-row cleanup is scheduled by you** — `oauth2/store/sql`
  runs no job of its own: rows — consumed and abandoned authorization codes
  included — stay until `Store.PurgeExpired` deletes those past
  `expires_at`. Schedule it, and add the `expires_at` indexes the package
  documentation lists: `Schema` creates none (MySQL has no `CREATE INDEX IF
  NOT EXISTS`, and building one at boot would block a populated table).
- **In-memory store growth** — `oauth2/storage/memory` never purges
  anything: consumed and expired codes, expired tokens and revoked
  families stay for the process lifetime. It is meant for development and
  tests only.
- **Tested servers** — CI runs the SQL store on SQLite and, in its
  "Store suites (real backends)" job (`make test-backends`), on
  PostgreSQL 16.15, MySQL 8.0.46 and 8.4.11 and MariaDB 11.4.13: the
  conformance suite, concurrent `Migrate` and the MySQL upgrade statements
  (`internal/interop/sqlstores`). The Redis store runs its conformance
  suite on Redis 7.4.11. Other versions, compatible engines, replicas and
  proxies are not tested: there the guarantees (row locks, READ COMMITTED
  on PostgreSQL, InnoDB on MySQL) rest on the locking semantics the
  package documentation describes.
- **SQL schema upgrades are manual** — `Store.Migrate` creates missing
  tables and never alters an existing one: the columns a release adds (#80's
  `consumed`, #83's `issuer` and `extension_data`, the codes'
  `redirect_uri_omitted`, the refresh tokens' `family_issued_at`), the
  binary key columns and the InnoDB engine of MySQL are added or converted
  with the statements MIGRATION.md lists, through your migration tool.
  `Migrate` — and `Store.CheckDeployment`, for a schema applied by your own
  tool — refuses a MySQL database still missing the engine or the binary
  keys; a missing column fails the statements that use it, closed.
- **Deployment checks see what the server reports** — `CheckDeployment`
  verifies on MySQL the engine, the key columns and the `sql_mode` of one
  pooled connection (set the strict mode server-wide or in the DSN), and on
  Redis what `INFO` reports. It checks nothing on PostgreSQL:
  `synchronous_commit=off` can lose an acknowledged revocation in a crash,
  but it can be set per role, session or transaction, so one connection's
  value proves nothing — keep it on. Replicas, proxies and eviction set
  after boot are not seen.
- **A leaked code can be burned** — codes are consumed before they are
  validated, so a party holding a code (but not its client's credentials or
  PKCE verifier) can make the legitimate exchange fail with
  `invalid_grant`; it obtains nothing. A deliberate trade-off, see
  [docs/security-considerations.md](docs/security-considerations.md).
- **Every registered client is trusted to receive error redirects** — an
  error `/authorize` detects before the resource owner authenticated is
  redirected to the client's registered redirect URI unless
  `AuthorizeConfig.TrustedRedirect` says the client is not trusted: by
  default — under `Profile20BCP` and `Profile21Draft` too — a deviation from
  the RFC 9700 §4.11.2 MUST ("The authorization server MUST always
  authenticate the user first … before redirecting the user"), which the
  hook closes; set it when clients are registered by third parties. It is
  deliberate: the library has no dynamic client registration (RFC 7591, the
  attacker's path in §4.11.2), so every client comes from the deployment's
  own registry, and OpenID Connect Core §3.1.2.6 expects `prompt=none`
  refusals to be redirected — a fail-closed default would turn them, and
  every other pre-authentication error, into bare pages for every
  deployment. An explicit denial after authentication (`access_denied`) is
  redirected to every client — RFC 9700 §4.11.2's second attack: a
  `ConsentFunc` may warn the resource owner about a client it does not
  trust.
- **Clients span every issuer by default** — with one `ClientStore` behind
  several issuers, a client is known at every issuer unless it implements
  `IssuerBoundClient` (`DefaultClient.IssuerValues`) or the store is scoped
  by issuer. Deliberate: the realms a client belongs to are data only the
  deployment has, a single-tenant server (`StaticIssuer`) has one realm, and
  codes and tokens are bound to their issuer whatever the client — one
  realm's authorization is never redeemed at another.
- **`/introspect` returns no `iss`** — an active token is always of the
  issuer the request resolved to; the token's issuer reaches an
  `IntrospectionPolicy` (`IntrospectedToken.Issuer`), not the response body.
- **`oauth2.Extension` scope** — it extends the `authorization_code` and
  `refresh_token` exchanges; the implicit flow runs its authorization hooks
  and records their context, but its fragment members are fixed (RFC 6749
  §4.2.2), and the `client_credentials` and `password` grants never call it.
  Response modes: `query` for the code flow, and `fragment` only for an
  enabled implicit flow — which the metadata advertises once an
  `AuthorizeHandler` enabling it is built, mounted or not: the server cannot
  observe which handler is mounted, so build only the handlers you mount (a
  request for a flow the mounted handler refuses gets
  `unsupported_response_type`); `form_post` is refused.

## OpenID Provider

`oidc/provider` serves the Authorization Code flow of OpenID Connect Core
1.0; [docs/oidc-provider.md](docs/oidc-provider.md) is the exact feature
matrix. Not supported, and never advertised:

- **Other flows and response modes** — the implicit and hybrid flows
  (`unsupported_response_type`, for plain OAuth 2.0 requests too:
  `Provider.AuthorizeHandler` refuses `AuthorizeConfig.AllowImplicit`),
  `form_post`, `fragment` and JARM response modes (refused by the core with
  a bare 400). Nothing refuses `AllowImplicit` on a handler built from
  `Provider.Server()`: never enable it there — the server would serve the
  implicit flow to plain OAuth 2.0 requests and advertise it in its RFC 8414
  metadata, which the discovery document would then contradict (RFC 9068
  §4).
- **Request objects and registration** — `request` and `request_uri` are
  refused (`request_not_supported`, `request_uri_not_supported`), and so is
  the `registration` parameter; clients are static (`oauth2.ClientStore`),
  without dynamic registration.
- **Subjects and token formats** — pairwise subjects, encrypted ID Tokens,
  signed or encrypted UserInfo responses, aggregated and distributed claims;
  `EdDSA`, `HS*` and `none` ID Token algorithms.
- **Sessions and logout** — Session Management, Front-Channel and
  Back-Channel Logout, RP-Initiated Logout (no `sid`, no
  `end_session_endpoint`); Self-Issued OP; WebFinger issuer discovery.
- **Client authentication** — `client_secret_jwt`, `private_key_jwt` and
  mTLS (the core's `client_secret_basic`, `client_secret_post` and `none`
  are).
- **Unknown scope values are refused** — a scope value outside the
  client's registration is `invalid_scope` (the oauth2 core's client
  policy), where Core §3.1.2.1 says unknown scope values SHOULD be ignored:
  a client registers every scope it requests, `openid` and
  `offline_access` included.
- **Scope claims in the ID Token** — the claims of `profile`, `email`,
  `address` and `phone` are released at UserInfo only (OIDC Core §5.4); a
  client wanting them in the ID Token requests them through the `claims`
  parameter. Consumers that only read the ID Token (e.g. an API server's
  `--oidc-username-claim=email`) need that request until an opt-in lands.
- **`redirect_uri` rules after the core's checks** — an OpenID request
  without `redirect_uri` is refused with a bare 400 (Core §3.1.2.1) once the
  oauth2 core accepted it; an error of the core's own checks (response
  type, scope, PKCE) comes first and is redirected, as for any OAuth 2.0
  request, to the client's sole registered redirect URI. A repeated
  `redirect_uri` is refused by the core itself, with a bare 400, before any
  other check.
- **Freshness to the second** — `prompt=login` and `max_age` are enforced
  at the second of `auth_time`: an authentication earlier in the same
  second as the request passes. An `Interaction` that must re-authenticate
  shows its login page itself. Deliberate: `auth_time` is a NumericDate in
  whole seconds (OIDC Core §2), and session stores often keep times to the
  second — a finer check would refuse a login completed within the second
  its interaction started.
- **`claims_locales` and language tags** — `claims_locales` reaches the
  `Interaction` only (OIDC Core §15.1's minimum): the `ClaimsSource` is not
  told, so matching requested locales (§5.2, a SHOULD) rests on the tagged
  claims it returns. Language tags are compared exactly — `name#FR` neither
  releases nor is released by `name#fr` — although §5.2 says to interpret
  them case-insensitively.
- **One release list for both targets** — `Decision.Claims` releases a
  requested claim in the ID Token and at UserInfo alike: an application
  cannot release a claim to one target only.
- **Access-token audience** — the provider refuses (`server_error`) every
  code exchange and refresh whose access-token audience is the requesting
  client's ID, or the ID of a client registered at the token's issuer that
  declares the `authorization_code` grant (such a client receives ID Tokens
  whose `aud` is its client ID). The first tokens of the `client_credentials`
  and legacy `password` grants never reach the provider (a refresh does):
  their audience is checked only through the code exchanges and refreshes
  of the same issuer. A client that declares `refresh_token` but no longer
  `authorization_code` still refreshes the OpenID grants it holds, yet is
  not counted. Keep every `IssuerResolver` audience apart from the client
  IDs of relying parties.
- **Claim-name aliasing beyond case variants** — the provider compares claim
  names ignoring case (simple and full case mappings), the diacritics
  lodash's `camelCase` strips from Latin letters, and every character but
  letters and decimal digits (`#` included); a tagged name whose claim name
  followed by any part of its tag reads as another claim
  (`email#verified-fr`) is refused. A relying party comparing names under
  compatibility normalization (NFKC: fullwidth `ｓｕｂ`), stripping other
  diacritics (`ṡ`, beyond Latin-1 and Latin Extended-A), under
  locale-sensitive collation, or reading confusable letters (Cyrillic `ѕ`)
  as Latin ones is not covered. The continuation rule also over-refuses: a
  tagged variant whose claim name followed by the first letters of its tag
  spells another known claim is never released — declaring `emails` drops
  `email#sv`; declaring `named` drops the standard `name#de-CH` and still
  releases `named#ech`, which a camelCase relying party comparing
  case-insensitively reads as `name#de-CH`. Keep application claim names
  from extending standard ones. An application claim missing from
  `Config.ClaimsSupported` is released under another spelling when requested
  alone, and dropped together with such a variant — an end-user can suppress
  it: declare every claim relying parties decide on.
- **Account checks of grants the provider did not approve** — the
  `ClaimsSource` stops, at its next exchange, an OpenID grant or a plain
  OAuth 2.0 grant approved through `Provider.AuthorizeHandler` whose
  end-user is gone (`ErrUnknownSubject`); a plain grant another
  `ConsentFunc` approved (`Server().AuthorizeHandler`), the `password`
  grant and access tokens already issued are not checked: revoke the
  end-user's token families too.
- **No UI, directory or CORS** — no login or consent pages, tenant
  directory or identity linking (the application's `Interaction`), and no
  built-in CORS, which UserInfo SHOULD support for browser-based clients
  (OIDC Core §5.3): add it as middleware.
- **Handlers do not check their path** — discovery and the JWK Set answer
  wherever they are mounted (behind `http.StripPrefix` or a rewriting proxy
  they cannot see the public path): mount them at their `Paths` only, since
  relying parties require the issuer to be the URL they fetched the
  document from (Discovery §4.3).
- **No certification** — the OpenID Foundation conformance suite's OP
  plans run locally (`make conformance`, results in
  [docs/oidc-conformance.md](docs/oidc-conformance.md)); a local run is no
  certification. Its Basic plan needs `oauth2.Profile20`: it sends PKCE in
  a single module, and the default profile refuses requests without it.
  `acr_values` stay voluntary (a warning of the suite when the application
  asserts no requested `acr`).

## OpenID Connect client

`oidc/client` is a Relying Party for the Authorization Code flow with
PKCE. Not supported, and refused where a provider could select them:

- **Other flows and response modes** — implicit and hybrid flows, the
  `fragment` response mode, JARM.
- **Request objects and pushed requests** — `request` / `request_uri`
  (JAR), PAR (RFC 9126), the `claims` request parameter.
- **ID Token formats** — encrypted ID Tokens (JWE), HMAC-signed ones
  (HS256/384/512), `alg=none`, and the fully-specified `Ed25519` algorithm
  identifier of RFC 9864 (go-jose v4.1.6 knows `EdDSA` only).
- **Keys named or carried by the ID Token** — an ID Token whose JOSE header
  holds `jwk`, `x5c`, `jku` or `x5u`, whatever its value, is refused
  (`ErrIDTokenMalformed`) before it is parsed: keys come from the issuer's
  `jwks_uri` only (OpenID Connect Core §2: ID Tokens SHOULD NOT use these
  members). RFC 7515 §4 would let a recipient ignore them; this is a local
  policy, with no opt-out: providers that send them are not supported
  (Cloud Foundry UAA and SAP BTP XSUAA put `jku` in their token headers).
  The 4 KiB bound on the decoded header has no opt-out either. RSA keys of
  the JWK Set outside 2048–4096 bits are ignored.
- **RSA keys without `alg`** — one algorithm per key (RFC 8725 §3.1): an
  RSA JWK without `alg` verifies RS256 only, or the single RSA algorithm of
  `Config.Algorithms`. A provider signing with PS256/384/512, RS384 or
  RS512 and publishing such keys needs `Config.Algorithms` set to that one
  algorithm.
- **Signed or encrypted UserInfo responses** (`application/jwt`):
  `UserInfo` returns `ErrUserInfoUnsupported`.
- **UserInfo token in the header only** — the access token goes in the
  `Authorization` header (RFC 6750 §2.1); a provider requiring the form
  body fails `UserInfo` (the conformance suite's
  `oidcc-client-test-userinfo-bearer-body`).
- **WebFinger** (Discovery §2) — not supported: configure the issuer.
- **`ExtraParams`** cannot override a parameter of the authorization
  endpoint's own query (RFC 6749 §3.1: no parameter twice), nor use another
  spelling — case, `.` for `_` — of a parameter the client sends or does not
  support.
- **Client authentication** — `private_key_jwt`, `client_secret_jwt` and
  mTLS; DPoP. `client_secret_basic`, `client_secret_post` and `none` are
  supported.
- **Token lifecycle** — no refresh-token helper (refresh tokens are
  returned to the application, which redeems them itself), no logout
  (RP-initiated, front- or back-channel), no dynamic client registration.
- **Claims** — aggregated and distributed claims are left unresolved in
  `Identity.Claims`. A lone member named like a known claim but for case
  (`EMAIL_VERIFIED`) is kept, as OpenID Connect Core §2 requires for claims
  not understood; only two names differing by case are refused. Decode
  claims with `DecodeClaims` / `UserInfo.Decode`, not `encoding/json`
  into a struct, which reads such a member as the known claim.
- **Provider metadata** — discovery is required: no static metadata. The
  metadata issuer must equal the configured issuer byte for byte, so
  templated multi-tenant issuers (Microsoft Entra `common` /
  `organizations`) are refused: configure the tenant's own issuer.
- **Discovery defaults** — the defaults of OpenID Connect Discovery §3 are
  not used to refuse a provider: a capability the provider lacks fails at
  run time. One exception: a public client (`none`) requires the provider
  to advertise S256 in `code_challenge_methods_supported`, which some
  providers omit although they support it.
- **A withdrawn provider key stays trusted for a while** — the provider's
  JWK Set is cached five minutes: a key the provider withdrew (a leaked
  one) keeps verifying ID Tokens until the next refresh. While the JWK Set
  fetches fail, the cached keys serve for up to 24 hours, so an attacker
  holding a withdrawn key and able to make those fetches fail (a network
  position, a denial of service on the `jwks_uri`) keeps it trusted that
  long — the availability trade-off of the `jwt` module's remote key sets.
  Rebuilding the `Client` drops the cache at once (OpenID Connect Core
  §10.1.1 sets no bound).
- **A leaked state burns the pending login** — an authorization response is
  not authenticated: any request to the callback carrying the state,
  through the victim's own browser (which presents the binding cookie on a
  top-level navigation), expires the binding cookie — and, with an error
  or a bogus code, consumes the transaction — so the genuine response
  fails and the user starts over. It cannot complete a login for the
  attacker. `AuthRequest` prints and logs without the state; its JSON
  encoding, the hand-off to a front end, keeps it.
- **RFC 9207 `iss` policy** — a response carrying `iss` from a provider
  that does not advertise `authorization_response_iss_parameter_supported`
  is discarded (`ErrIssuerParameter`, RFC 9207 §2.4) unless
  `Config.RequireIssParameter` declares that the provider sends it. Without
  `RequireIssParameter` on every connection, distinct redirect URIs remain
  the only mix-up defense against a provider that sends no `iss`, with the
  gap RFC 9700 §4.4.2.2 names (docs/oidc-client.md, "Connections and
  redirect URIs").
- **ID Tokens are expected in RS256** — the default of OpenID Connect Core
  §3.1.3.7 step 7: a provider signing with another algorithm fails every
  login (`ErrIDTokenAlgorithm`, or `ErrInvalidMetadata` at `New` when it
  does not list RS256) until `Config.Algorithms` names the algorithm
  registered for the client.
- **`acr_values` makes `acr` required** — when sent, the ID Token must
  carry one of the requested values; list every acceptable level.
- **No OpenTelemetry spans** — `oidc/client` and `outbound` return errors
  to the caller and emit no spans.
- **Reverse proxies** — `HandleCallback` takes the host of the received
  URL from the Host header and its scheme from the redirect URI: a proxy
  must preserve the Host header, and one rewriting hosts or paths needs
  `Complete` with the public URL. Forwarded headers (`X-Forwarded-Host`,
  RFC 7239) are never read: only the application knows which proxy to
  trust.
- **Transaction stores** — the store is trusted for availability and single
  consumption: its integrity is not needed (the transaction MAC is keyed by
  the binding secret and a server-held transaction key the store never
  sees), but a store that loses or resurrects transactions fails or replays
  logins. Removing a transaction key before `TransactionTTL` has elapsed
  fails the logins it protected. `oidc/client/storage/memory` keeps
  transactions in the process: use the SQL or Redis store when several instances serve
  callbacks. It keeps at most `memory.DefaultCapacity` (10 000) pending
  logins, or the bound of `memory.WithCapacity(n)`: login starts are
  unauthenticated, so size it — about 0.5 KB per pending login plus its
  `AppState` (up to 4 KiB), kept for `TransactionTTL` — and rate-limit
  login starts, since a full store refuses every new login
  (`memory.ErrFull`) until transactions expire or are consumed.
  `oidc/client/store/sql` ships `PurgeExpired`, a single
  unbatched `DELETE` the operator schedules (index `expires_at`, see its
  package documentation). CI (`make test-backends`) runs the conformance
  suite and the replica races of the SQL and Redis stores on PostgreSQL
  16.15, MySQL 8.0.46 (end of life since April 2026) and Redis 7.4.11
  (`internal/interop/oidcstack`, `TestRealBackend*`), and the concurrent
  `Migrate` of the SQL store also on MySQL 8.4.11 and MariaDB 11.4.13
  (`internal/interop/sqlstores`); other versions are not tested. On Redis,
  a consumption acknowledged by a primary that fails before replicating it
  can be lost in a failover, making the transaction consumable again:
  single use then rests on the provider's single-use authorization code
  and on the binding secret only the user agent holds. The browser test of
  the binding cookie (`internal/interop/oidcrp`, headless Chrome,
  `OIDC_BROWSER_TESTS=1`) and the live discovery check against six real
  providers (`OIDC_LIVE_DISCOVERY=1`) are opt-in and do not run in CI.
- **Opt-in evidence** — the end-to-end suites (`make e2e-oidc`), the
  conformance-suite runs (`make conformance`), the browser and live checks
  need Docker, Chrome, Tales or the Internet and run locally only;
  [docs/oidc-conformance.md](docs/oidc-conformance.md) keeps
  their latest results and the release checklist.
- **Provider metadata in the wild** — of the six providers of the pinned
  corpus, only Auth0 lists `none` in `token_endpoint_auth_methods_supported`:
  a public client is refused at `New` by the others (Google, Microsoft
  Entra, Apple, GitLab, Salesforce), and Apple offers `client_secret_post`
  only. A provider ignoring `acr_values` fails every login that sends them
  (`ErrIDTokenACR`).

## JWT (`jwtsec`)

- **Token strings are not unique** — an ECDSA signature has a second valid
  form (s and n − s): the verifier accepts both, since RFC 7518 §3.4 sets no
  low-S rule and refusing the "high" one would refuse half of the legitimate
  tokens of other signers. Never key a cache, replay check or deny-list on
  the token string; use `jti`. An `ActiveTokenCheck` looking tokens up in
  the store accepts only the string the server issued, and so refuses the
  twin.
- **Untyped access tokens** — `BearerVerifier` accepts only access tokens
  typed `at+jwt` (RFC 9068 §4), or the type named by `WithAccessTokenType`.
  An authorization server that sends no `typ` cannot be served by it: wrap
  a `NewVerifier` configured with `WithIssuer` and `WithAudience` in your own
  `bearer.VerifierFunc`, knowing that its access tokens are then told apart
  from its ID Tokens by their audience only. `WithAccessTokenType("JWT")`
  carries the same caveat: it is safe only when the resource server's
  audience is never the `client_id` of a client of that issuer.
- **Claims decoding** — claims, `claimsOut` included, are decoded by
  go-jose's case-sensitive fork of `encoding/json` (Go 1.6): `claimsOut`
  fields need exact `json` tags (an untagged `Email` field no longer receives
  `email`), `encoding/json.Number` fields are not supported (use `float64`,
  `int64` or `json.RawMessage`), and the content of `claimsOut` is
  unspecified when `Verify` fails. Claim names equal under Unicode case
  folding are refused, which is stricter than RFC 7519 §4 (that allows
  `"sub"` next to `"Sub"`).
- **Key identifiers** — a `kid` shared by several keys designates no key,
  even keys of different types that RFC 7517 §4.5 allows to share one; a
  token without `kid` is verified against a single-key set only. Signers
  write their key's `KeyID` as the `kid` of every token, HMAC included: a
  verification key must carry the same `KeyID`.
- **Remote JWK Set policy** — the TTL is configurable (`WithCacheTTL`); the
  minimum refresh interval (10 s), the back-off cap (5 minutes), the
  maximum staleness (24 h), the 100-key and 2048–4096-bit RSA bounds, the
  10 s and 1 MiB fetch bounds are not. An RSA key published without `alg`
  verifies RS256 when the verifier allows it, otherwise the verifier's only
  RSA algorithm, otherwise nothing: publish `alg` on RSA keys signing
  PS256/384/512. A JWK Set URL redirecting to another origin cannot be
  used, whatever `MaxRedirects`: configure the final URL.
- **RSASSA-PSS salt** — PS256/384/512 signatures must use a salt of the
  hash size (RFC 7518 §3.5): tokens of signers using another — go-jose's
  `cryptosigner.Opaque` over an in-process key outside FIPS 140-3 mode,
  Vault Transit with its default `salt_length=auto`, the OpenSSL tools
  before 3.1, `rsa.SignPSS(…, nil)` — are refused, and `Sign` fails for
  such an opaque signer.
- **No JWS extension, nested JWT or JWE** — tokens whose header uses `crit`
  or `b64` are refused, and a nested JWT (`cty: JWT`, RFC 7519 §7.2 step 8)
  is refused because its payload is not a claims object.
- **No key in the token header** — a token whose JOSE header holds `jwk`,
  `x5c`, `jku` or `x5u`, whatever its value, is refused
  (`ErrMalformedToken`) by `Verifier`, `VerifySignature` and
  `BearerVerifier`, with no opt-out. RFC 7515 §4 would let a recipient
  ignore these members; refusing them is a local policy (keys come from the
  configured key set only: RFC 9068 §4, RFC 8725 §3.10). Issuers that send
  them are not supported: Cloud Foundry UAA and SAP BTP XSUAA put `jku` in
  every token header. `x5t` and `x5t#S256` are accepted and ignored.
- **RSA key sizes** — signing and published keys are 2048–4096 bits
  (`NewSigner` and `MarshalJWKS` refuse larger ones: once published, this
  library's key sets ignore such a key and go-jose ≥ v4.1.6's
  `JSONWebKeySet`, used by go-oidc among others, refuses the whole JWK Set),
  and so are the keys of a remote JWK Set; verification keys given to
  `NewStaticJWKS` have no upper bound.
- **Size bound** — tokens over 16 KiB are refused by default
  (`WithMaxTokenSize` on a `Verifier`); `VerifySignature` always applies
  the default bound. A JOSE header over 4 KiB decoded is refused whatever
  the token bound, with no option.

## Outbound requests

- **No proxy support** — `outbound` clients never use a proxy: the
  connect-time address check would judge the proxy, not the destination.
  Deployments whose egress must go through a proxy cannot use them yet.
- **Ports are not restricted** by default — restrict them in
  `Policy.CheckAddr`, which sees the numeric port dialed (`Policy.CheckURL`
  sees a canonical port too).
- **Private networks** need an explicit `AllowedPrefixes` exemption.
- **NAT64** — only the well-known prefix (`64:ff9b::/96`) is decoded and
  judged on its embedded IPv4 address. A network-specific prefix (RFC 6052
  §2.2) is carved from global unicast space, so its addresses pass as
  ordinary global IPv6 and reach whatever IPv4 address they embed, private
  ones included: a network translating such a prefix must refuse it in
  `Policy.CheckAddr`.
- **Error text** — a dial error never names the resolved address nor the
  resolver, but an error after the connection is made (a reset, a read
  timeout) comes from the standard library and may name the address and
  port.

## SAML Service Provider

- **Not supported** — Single Logout, IdP-initiated SSO (unsolicited
  responses are refused), the HTTP-Artifact and other bindings, encrypted
  assertions (refused with `ErrEncryptedAssertionUnsupported`), the IdP
  role, and signed metadata: an embedded signature is not verified.
  Importing administrator-provided metadata is the act of trust; fetched
  metadata is trusted through TLS to the configured URL and the pinned
  entity ID, so federation aggregates (whose trust comes from their
  signature) must not be used as metadata sources.
- **Metadata refresh** — a `MetadataSource` refreshes lazily, on use: an
  idle connection is refreshed at its next login. A document that expires
  is refreshed at once but at most once per `RetryInterval`, so a document
  valid for less than that fails closed for the rest of the interval.
  While refreshes fail, the last good document — and a key the IdP has
  withdrawn since — is used for up to `MaxStale` (7 days by default, never
  past its `validUntil`); lower it, down to `MaxRefresh`, to shorten that
  window.
- **Legal but ambiguous responses are refused** — several assertions,
  `SubjectConfirmation`s or `AuthnStatement`s, an assertion without
  `NameID`, a Response without `Issuer`. Configure the IdP to send one
  assertion with a persistent NameID; see
  [docs/security-considerations.md](docs/security-considerations.md#ambiguous-responses-are-refused)
  for AD FS, Entra ID, Okta and Keycloak.
- **At most 450 XML elements per response** (`MaxResponseElements`, sized
  from goxmldsig's canonicalization budget): a response carrying hundreds
  of group memberships is refused with `ErrResponseTooLarge`. Filter the
  groups the IdP releases to the application.
- **SHA-1** is refused unless the connection sets `InsecureAllowSHA1`;
  inclusive C14N and RSASSA-PSS (Keycloak's `RSA_SHA256_MGF1`) are never
  accepted.
- **ECDSA** signature values are verified as ASN.1 DER (goxmldsig): IdPs
  emitting the XML Signature 1.1 raw `r‖s` encoding fail closed. The SP
  signs AuthnRequests with RSA only.
- **IdP certificate rollover** — a certificate carried in a signature's
  `KeyInfo` must equal a trusted one: import the IdP's new certificate
  (refresh its metadata) before the IdP signs with it. Without `KeyInfo` —
  or with a `KeyInfo` that carries no certificate, which counts as absent —
  only the three most recent valid certificates of the connection are
  tried, the one that verified its last such signature first. Validity is
  checked at `now − ClockSkew`, so a certificate whose validity starts at
  the rollover is accepted only `ClockSkew` later.
- **Metadata keys** — each imported certificate is trusted as a signing key
  by itself (no chain building): a signing `KeyDescriptor` carrying several
  certificates, such as the IdP's certificate chain, two `KeyInfo`
  elements, or a `ds:KeyValue` / `dsig11:DEREncodedKeyValue` that is not
  its certificate's key (EC and DSA key values cannot be compared and are
  refused too), is refused (`ErrInvalidMetadata`). Identifier hints
  (`KeyName`, `X509SubjectName`, `X509IssuerSerial`, `X509SKI`,
  `X509Digest`) are neither verified nor used: the published certificate is
  the key, whatever they name. An IdP that publishes its
  chain cannot be followed through `FetchIdentityProviderMetadata` or
  `MetadataSource` (each refresh fails; the last good document is served up
  to `MaxStale`): import an edited copy keeping only the signing
  certificate — never a CA certificate, which would become a signing key.
  The SAML Metadata Interoperability Profile §2.6.1 is not followed where
  it would accept more: the certificate, not only its key, is trusted (a
  certificate re-issued over the same key must be imported first), its
  validity window is enforced, and `ds:KeyValue`-only keys are not
  imported. See
  [docs/saml-sp.md](docs/saml-sp.md#34-metadata-trust).
- **Clock skew cannot be zero** — `ClockSkew: 0` means the 3-minute
  default; one nanosecond is the strictest setting.
- **XML attribute names** — an element of a response carrying two
  attributes of one local name (whatever their prefixes), a prefixed
  attribute named like a SAML or XML-DSig attribute, or an attribute in the
  `xml` namespace other than `xml:lang`, `xml:space`, `xml:base` and
  `xml:id`, is refused: parsers disagree on such documents. No IdP is known
  to emit them.
- **Legacy browsers** that mishandle `SameSite=None` (Safari on iOS 12 and
  macOS 10.14, Chrome 51–66) drop the binding cookie: their logins fail
  with `ErrMissingBrowserBinding`.
- **Login CSRF by forced initiation** — `BeginLogin` cannot tell whether
  the user meant to start a login: the application must start logins only
  from a same-origin gesture (see
  [docs/saml-sp.md](docs/saml-sp.md#5-sessions-and-logout)).
  `examples/saml-sp` refuses a login whose `Sec-Fetch-Site` is missing,
  `cross-site` or `same-site`: browsers without Fetch Metadata (Safari and
  iOS before 16.4) cannot sign in to it, it needs an https or loopback
  origin, and `none` still admits a login forced through a link opened
  from another application (a mail client); only a CSRF-protected POST
  closes that.
- **Login CSRF through a leaked in-flight request** — the IdP redirect URL
  carries the request ID and the RelayState handle. Whoever learns it
  while the login is pending (`TransactionTTL`) can sign the victim in as
  herself, or burn the victim's login with a forged response, from a page
  the victim visits. `Connection.ResponseOrigins` refuses such POSTs, but
  only for an IdP whose page lets browsers send its origin: Keycloak's
  default realm sends `Referrer-Policy: no-referrer`, so browsers post
  `Origin: null`, which no check can tell from an attacker's page. Keep the
  TTL short and never log full IdP redirect URLs.
- **One verification per login** — a response refused after the browser
  binding and transaction checks consumes the transaction: a legitimate
  response refused there (an IdP key not imported yet, clock drift) makes
  the user start the login over.
- **Stores are trusted for availability and single consumption** — a MAC
  under `Config.TransactionKeys` protects the content of each transaction,
  not its existence or its consumed flag: a writer of the stores can delete
  pending logins, or let a transaction and an assertion be used again. The
  keys are the records' only integrity protection: a leaked key together
  with write access to the store allows rebinding again (rotate at once).
- **Host forwarding** — `CompleteLogin` compares the request's `Host` with
  the ACS URL's host and reads no forwarding header: behind a proxy that
  rewrites `Host`, forward the original, or pass `CompleteLogin` a copy of
  the request whose `Host` comes from the trusted proxy's header.
- **Stores** — `saml/sp/storage/memory` (development and tests) sweeps its
  expired records every 64 writes on its own clock (`memory.WithClock`) and
  is otherwise unbounded: it holds the login rate times `TransactionTTL`.
  `saml/sp/store/sql` deletes expired rows only when its `PurgeExpired`
  runs: schedule it. CI runs the stores on
  SQLite and miniredis, and (`make test-backends`) their races,
  conformance suite and payload round trip on PostgreSQL 16.15, MySQL
  8.0.46 (end of life since April 2026) and Redis 7.4.11
  (`internal/interop/saml`), and the concurrent `Migrate` of the SQL store
  also on MySQL 8.4.11 and MariaDB 11.4.13 (`internal/interop/sqlstores`);
  other versions are not tested.
- **SP key rollover with Keycloak** — a Keycloak SAML client keeps one SP
  signing certificate: `AdditionalSigningCertificates` cannot announce the
  next key there, and the client's certificate must be replaced when the
  SP switches.
- **Interoperability** — CI runs the SP against crewjam/saml's IdP and
  replays 15 pinned Keycloak responses (26.7.4 and 26.0.7). Live runs
  against Keycloak 26.7.4 and the browser suite (Chrome 155) are opt-in;
  no other IdP (AD FS, Entra ID, Okta, Shibboleth) and no other browser
  engine is tested. See
  [docs/saml-sp.md](docs/saml-sp.md#interoperability-evidence).

## Transports

- Only the `net/http` (`httpsec`), gRPC (`grpcsec`) and ConnectRPC
  (`connectrpcsec`) adapters are shipped. Other transports can be added
  downstream by implementing `security.Carrier` (header fields only — never
  the URL or cookies) and mapping errors with `security.ErrorClass`.
- **One challenge scheme per middleware** — the default error mappers
  advertise the one scheme configured with `WithChallengeScheme`, even when
  the engine accepts several (Basic and Bearer): RFC 9110 §11.6.1 allows a
  401 to list several challenges, but a client is only told about that
  scheme. Use one middleware per scheme, or a custom `ErrorMapper` that
  writes every challenge.
- **Basic credentials are not NFC-normalized** — a Basic challenge
  advertises `charset="UTF-8"`, which per RFC 7617 §2.1 says the server
  expects the user-id and password in Unicode Normalization Form C: clients
  are to send them normalized, and `basic` checks them as received. The
  dependency policy keeps `basic` and `password` off `golang.org/x/text`:
  normalize passwords with the hasher decorator of the `password` package
  documentation, user-ids in your `UserLoader` — and the attempt-limiter
  subject alike (`basic.WithAttemptSubject`).

## Attempt limiting

- **Opt-in** — `basic.Authenticator` limits failed attempts only with
  `basic.WithAttemptLimiter`; the OAuth2 endpoints take no
  `security.AttemptLimiter` yet: limit their failed attempts at the edge.
- **A throttle, not a lock-out** — `throttle.MemoryLimiter` slows guessing
  down; NIST SP 800-63B-4 §3.2.2 caps consecutive failures at 100 "by
  disabling that authenticator", which needs persistent state: an
  `AttemptLimiter` over your account store, or an account flag your user
  loader reports locked.
- **One process** — its budgets live in memory: each instance of a
  deployment has its own, and a restart forgets them. Share an
  `AttemptLimiter` over a common store for a global limit.
- **Lock-out and shared addresses** — the per-subject budget lets a
  distributed attacker lock an account out for as long as the attack lasts
  (turn it off, `Unlimited`, for credentials that cannot be guessed, such as
  OAuth 2.0 client secrets); the per-source budgets are shared by every
  client behind one IPv4 address or inside one IPv6 /56 — a NAT, a proxy
  whose forwarded address the application does not store, providers that
  number customers inside one /56, a NAT64 or SIIT translator mapping every
  IPv4 client into one prefix (store the embedded IPv4 address with
  `security.WithClientAddr`).
- **Unknown sources** — an attempt whose source is unknown (the zero
  address: a Unix-socket listener, an unparsable forwarded address) skips
  both source budgets and meets only the per-subject one; with that budget
  off, no budget applies and `Allow` refuses the attempt as unavailable
  (503) until the client address is supplied.
- **Reservations count** — an attempt counts as failed until it is settled:
  more concurrent attempts against one key than its allowance are refused,
  legitimate ones included. Reservations are counted per key: a settlement
  arriving after its own charges expired may settle a newer reservation of
  the key, letting a burst exceed its allowance by that many attempts
  (never the long-run rate).
- **No limit across subjects and sources** — a password-spraying campaign
  from many sources against many accounts is bounded only per source and
  per account: rate-limit at the edge.

## HTTP Basic

- **Attempt limiting is opt-in** — NIST SP 800-63B-4 §3.2.2 requires
  verifiers to limit failed attempts: without `WithAttemptLimiter` the
  `Authenticator` only caps the number of concurrent verifications
  (`runtime.GOMAXPROCS(0)` by default). See
  [Attempt limiting](#attempt-limiting) for what the shipped limiter does
  not cover.
- **Timing equalization residuals** — every attempt costs one verification,
  but a stored hash made with other parameters than the hasher's costs
  another time until it is re-hashed (`PasswordRehasher`), and the
  `UserLoader`'s own latency (a cache hit for a known user) is outside the
  library's control.
- **UTF-8 only** — Basic credentials must be UTF-8 (the challenge advertises
  `charset="UTF-8"`, RFC 7617 §2.1); clients sending ISO-8859-1 non-ASCII
  credentials are refused. User-ids and passwords are not normalized.
- **Format and separator characters refused** — a password containing a
  Unicode format character (an emoji sequence joined with U+200D, a soft
  hyphen, a byte order mark) or a line or paragraph separator no longer
  signs in with Basic: reset it, and refuse these characters when passwords
  are set (RFC 8265 OpaqueString). The same goes for a user-id — a Persian
  or Indic name written with U+200C or U+200D, for instance: rename the
  account or give it an alias without them.

## Passwords

- **No Unicode normalization** — the hashers hash a password's bytes as
  given, so a password typed in NFD on one device and NFC on another does
  not verify. NIST SP 800-63B-4 §3.1.1.2 says verifiers SHOULD apply NFC:
  wrap the hasher in the decorator shown in the `password` package
  documentation. Not built in: normalization needs `golang.org/x/text`,
  which the dependency policy keeps out of `password`, and normalizing by
  default would stop verifying the hashes of systems that never
  normalized.
- **bcrypt: 72 bytes** — longer passwords are refused (`ErrPasswordTooLong`),
  which caps passwords of multi-byte characters below the 64 characters
  SP 800-63B-4 asks verifiers to permit. Hashes imported from an
  implementation that truncated silently need the migration wrapper of
  MIGRATION.md. Prefer Argon2id.

## Sessions

- The session module is stateless by design: the whole session lives in an
  encrypted cookie, there is no server-side session store. A session can be
  revoked before its cookie expires only through `session.WithValidator`
  checking a store of the application's (no Redis/SQL store is shipped):
  record a fingerprint of the session ID at logout, or a "valid since"
  time per user, and refuse the sessions that match (OWASP ASVS V3.3).
  Otherwise a copy of the cookie stays valid until its deadline, `Logout`
  deleting the browser's copy only.
- With a cookie name that is not `__Host-` (a `Domain`, another `Path`,
  plain HTTP), a sibling host can plant a cookie of the session's name. A
  signed-in browser then carries two valid sessions and has none until that
  cookie expires (denial); a signed-out browser carries only the planted
  one and is signed into the attacker's account (login CSRF). The default
  `__Host-session` prevents both.
- One active session key seals at most 2^32 cookies (random GCM nonces,
  NIST SP 800-38D §8.3): the library does not count seals — a per-process
  count would miss the other instances — so rotate the key by volume
  (about 50 days at 1 000 cookie writes per second).
- The session cookie is read through `httpsec.Carrier` (its
  `CookiesNamed` accessor). The `grpcsec` and `connectrpcsec` carriers expose
  no cookies: a cookie session does not authenticate gRPC or ConnectRPC
  calls (Connect-Web clients included).

## Logging

- **What `fmt` cannot redact** — the types that hold secrets
  (`oauth2.DefaultClient`, the `jwtsec` keys, signers and key sets,
  `session.Codec` and `session.Session`, the `basic`, `bearer` and
  `session` authentications, `security.AttemptKey`…) print redacted with
  every `fmt` verb and in `slog` output — as do the `grpcsec` and
  `connectrpcsec` carriers, which print metadata key counts only — but fmt
  prints some values without
  calling any of their methods: `%p` of a value that is not a pointer, a
  value held in an unexported field of your own types, and — for the verbs
  a pointer does not take (`%s`, `%q`…) — what a nested pointer points to.
  Log these types directly or through exported fields, with `%v`.
  `oidc/client` holds every credential in an `oidcclient.Secret`, which
  `fmt` prints as an address there; what such a path still prints of its
  values is not a `Secret`: a `Callback`'s parameters (the authorization
  code, useless without the PKCE verifier derived from the binding secret,
  and the state), an `AuthRequest`'s URL — every request parameter in
  clear: the state, the `login_hint` (personal data) and the
  `id_token_hint` (an ID Token) — and an `Identity`'s claims.
- **Reflection dumpers** — a dumper that walks unexported fields and
  dereferences pointers without calling methods prints every value it
  reaches, an `oidcclient.Secret`'s included: go-spew with
  `DisableMethods`, which testify's failure diffs use. Dump these values
  that way in tests only, and mind that test output lands in CI logs. A
  struct embedding an `oidcclient.Secret` is promoted its methods and
  prints and encodes as `REDACTED` as a whole: name the field.
- **JSON** — `slog`'s JSON handler calls `LogValue` for attribute values
  only: a value nested in another one (a struct field, a map) is encoded
  with `encoding/json`. `oidcclient` values and `session.Session` encode
  without their secrets — an `oidcclient.Secret` encodes `REDACTED` — but
  `oidcclient.Identity` encodes its claims and `UserInfo` its claims
  (personal data): log these as attributes of their own. Other
  reflection-based encoders write every exported field: `encoding/gob`
  refuses any value holding an `oidcclient.Secret` (a gob-encoded session
  holding an `Identity` fails to save), and `encoding/xml` and YAML write
  it empty. Persist the identifiers and the revealed tokens in a struct of
  your own.
- **Credentials and tokens in flight are not redacted yet** — the `oauth2`
  records (`AuthorizationCode`, `AccessToken`, `RefreshToken`, the
  `GrantResponse` holding them) print the raw code and tokens they carry
  during issuance: never log them.

## Tooling

- The tests use mockery mocks generated by `make generate` and never
  committed. A published module's tests (from its module zip: `go test all`,
  `go vet` from the module cache, distribution builds) only compile from a
  repository checkout after `make generate`; the library code builds without
  them.
- **Advisories outside every database** — the CI scanners (govulncheck,
  OSV-Scanner) and Dependabot only see advisories that reached the Go
  vulnerability database or the GitHub Advisory Database. A security
  advisory a dependency publishes in its own repository reaches neither
  until GitHub reviews it, and the ones without a CVE are in practice never
  reviewed: 15 such advisories against 6 dependencies of the workspace
  since July 2026, among them go-jose's GHSA-mgcc-cww5-fp2q. They are
  checked by hand before a release ([docs/releasing.md](docs/releasing.md)).
- **Tool modules are not scanned** — `tools/*` hold no package, so neither
  govulncheck nor OSV-Scanner can analyse them; Dependabot alerts and
  version updates are the only signal for the development tools, which run
  in CI with a read-only token. Scanning the built tool binaries
  (`govulncheck -mode=binary`) is a planned follow-up.

## Not planned

- **`HTTPDigestFilter` (RFC 7616)** — Digest auth is effectively dead; it
  will not be implemented unless a concrete need surfaces.
- **LDAP / API-key authenticators** — easy to add downstream as
  `security.Authenticator` implementations; not shipped in the core library.
- **DPoP (RFC 9449)** and **JWE** — out of scope for the initial release;
  candidates for a later minor version.
