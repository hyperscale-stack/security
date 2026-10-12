# Known limitations

The library covers HTTP and gRPC transports, HTTP Basic / Bearer schemes,
password hashing, JWT, OAuth2 (issuer + resource server), OpenID Connect
(provider and relying party), a SAML 2.0 Service Provider, production
storage backends, and stateless cookie sessions. This document tracks what is
**not** yet covered. Remaining items are tracked as GitHub issues rather than
future refactor phases.

## OAuth2 server

- **`private_key_jwt` client authentication (RFC 7523)** — not implemented.
  `client_secret_basic`, `client_secret_post`, and `none` are.
- **`/.well-known/jwks.json` endpoint** — the `oauth2` module alone serves
  none, although its RFC 8414 metadata advertises `jwks_uri`: mount the
  `oidc/provider` `JWKSHandler`, which serves the issuer's public keys, or
  publish your own with `jwtsec.MarshalJWKS` (it refuses private and
  symmetric keys).
- **Offline JWT access tokens are not revocable** — a token-family
  revocation takes effect in the store, not at resource servers verifying
  JWT access tokens offline (`jwtsec.BearerVerifier`): the RFC 9068 payload
  carries a `jti` but no family, and no deny-list is shipped, so such a token
  stays valid until it expires. Keep their lifetime short, or validate
  against the store. See
  [docs/security-considerations.md](docs/security-considerations.md#offline-jwt-access-tokens).
- **Redis Cluster** — not supported by `oauth2/store/redis`: its Lua
  scripts touch keys of several hash slots. Use a standalone server or a
  Sentinel primary.
- **SQL expired-row cleanup** — `oauth2/store/sql` ships no expiry job:
  rows — consumed and abandoned authorization codes included — stay until
  an operator deletes those past `expires_at` (see the package
  documentation for a safe order).
- **In-memory store growth** — `oauth2/storage/memory` never purges
  anything: consumed and expired codes, expired tokens and revoked
  families stay for the process lifetime. It is meant for development and
  tests only.
- **PostgreSQL and MySQL are not exercised in CI** — the SQL store's tests
  run on SQLite only; its PostgreSQL and MySQL guarantees (row locks,
  READ COMMITTED on PostgreSQL, InnoDB on MySQL) are argued from their
  locking semantics, not tested.
- **SQL schema upgrades are manual** — `Store.Migrate` creates missing
  tables and never alters an existing one: the columns a release adds (#80's
  `consumed`, #83's `issuer` and `extension_data`, the codes'
  `redirect_uri_omitted`) are added with the statements MIGRATION.md lists,
  through your migration tool.
- **RFC 9207 `iss` needs a resolved issuer** — every authorization response
  names its issuer, except the `server_error` redirected when the
  `IssuerResolver` itself fails: no issuer is known then, so it travels
  without `iss`, and an RFC 9207 client rejects it (RFC 9207 §2.4) — the
  outcome a failed request has anyway. This deviates from RFC 9207 §2
  ("including error responses") on purpose; a bare 500 was the reviewed
  alternative (see
  [docs/security-considerations.md](docs/security-considerations.md)).
- **The issuer is not validated by the core** — `iss` carries what the
  `IssuerResolver` returns; RFC 9207 §2 wants an https URL without query or
  fragment. `oidc/provider` refuses any other issuer (`server_error`), but
  that refusal still names it.
- **Clients span every issuer by default** — with one `ClientStore` behind
  several issuers, a client is known at every issuer unless it implements
  `IssuerBoundClient` (`DefaultClient.IssuerValues`) or the store is scoped
  by issuer.
- **`/introspect` returns no `iss`** — the token's issuer reaches an
  `IntrospectionPolicy` (`IntrospectedToken.Issuer`), not the response body.
- **The `nonce` parameter is not bounded by the core** — `/authorize` records
  it as sent; `oidc/provider` bounds it in OpenID requests (512 bytes).
- **`oauth2.Extension` scope** — it extends the `authorization_code` and
  `refresh_token` exchanges; the implicit flow runs its authorization hooks
  and records their context, but its fragment members are fixed (RFC 6749
  §4.2.2), and the `client_credentials` and `password` grants never call it.
  Response modes: `query` for the code flow — the only one the metadata
  advertises — and `fragment` only for an enabled implicit flow; `form_post`
  is refused.

## OpenID Provider

`oidc/provider` serves the Authorization Code flow of OpenID Connect Core
1.0; [docs/oidc-provider.md](docs/oidc-provider.md) is the exact feature
matrix. Not supported, and never advertised:

- **Other flows and response modes** — the implicit and hybrid flows
  (`unsupported_response_type`), `form_post`, `fragment` and JARM response
  modes (refused by the core with a bare 400).
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
  shows its login page itself.
- **Account checks of plain OAuth 2.0 grants** — the `ClaimsSource` stops an
  OpenID grant whose end-user is gone (`ErrUnknownSubject`), but a grant
  without `openid` carries no provider context and is not checked: revoke
  the end-user's token families too.
- **No UI, directory or CORS** — no login or consent pages, tenant
  directory or identity linking (the application's `Interaction`), and no
  built-in CORS.
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
  identifier of RFC 9864 (go-jose v4.1.5 knows `EdDSA` only).
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
  callbacks. It is unbounded unless built with `memory.WithCapacity(n)`:
  login starts are unauthenticated, so size it — about 0.5 KB per pending
  login plus its `AppState` (up to 4 KiB), kept for `TransactionTTL` — and
  rate-limit login starts, since a full store refuses every new login
  (`memory.ErrFull`) until transactions expire or are consumed.
  `oidc/client/store/sql` ships `PurgeExpired`, a single
  unbatched `DELETE` the operator schedules (index `expires_at`, see its
  package documentation), and its PostgreSQL and MySQL guarantees are not
  exercised in CI (SQLite only) — the opt-in runs of
  `internal/interop/oidcstack` (`TestRealBackend*`, `compose.yaml`) cover
  them, with Redis, locally. On Redis, a consumption acknowledged by a
  primary that fails before replicating it can be lost in a failover,
  making the transaction consumable again: single use then rests on the
  provider's single-use authorization code and on the binding secret only
  the user agent holds. The browser test of the binding cookie
  (`internal/interop/oidcrp`, headless Chrome, `OIDC_BROWSER_TESTS=1`) and
  the live discovery check against six real providers
  (`OIDC_LIVE_DISCOVERY=1`) are opt-in and do not run in CI.
- **Opt-in evidence** — the end-to-end suites (`make e2e-oidc`), the
  conformance-suite runs (`make conformance`), the real-backend, browser
  and live checks need Docker, Chrome, Tales or the Internet and run
  locally only; [docs/oidc-conformance.md](docs/oidc-conformance.md) keeps
  their latest results and the release checklist.
- **Provider metadata in the wild** — of the six providers of the pinned
  corpus, only Auth0 lists `none` in `token_endpoint_auth_methods_supported`:
  a public client is refused at `New` by the others (Google, Microsoft
  Entra, Apple, GitLab, Salesforce), and Apple offers `client_secret_post`
  only. A provider ignoring `acr_values` fails every login that sends them
  (`ErrIDTokenACR`).

## Outbound requests

- **No proxy support** — `outbound` clients never use a proxy: the
  connect-time address check would judge the proxy, not the destination.
  Deployments whose egress must go through a proxy cannot use them yet.
- **Ports are not restricted** by default — restrict them in
  `Policy.CheckURL`.
- **Private networks** need an explicit `AllowedPrefixes` exemption.
- **NAT64** — only the well-known prefix (`64:ff9b::/96`) is decoded and
  judged on its embedded IPv4 address. A network-specific prefix (RFC 6052
  §2.2) is carved from global unicast space, so its addresses pass as
  ordinary global IPv6 and reach whatever IPv4 address they embed, private
  ones included: a network translating such a prefix must refuse it in
  `Policy.CheckAddr`.
- **Error text** — a refused destination is never named, but the errors of
  allowed destinations (refused connection, timeout, TLS failure) come
  from the standard library and may name the resolved address and port.

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
  (refresh its metadata) before the IdP signs with it. Without `KeyInfo`,
  only the three most recent valid certificates of the connection are
  tried. Validity is checked at `now − ClockSkew`, so a certificate whose
  validity starts at the rollover is accepted only `ClockSkew` later.
- **Clock skew cannot be zero** — `ClockSkew: 0` means the 3-minute
  default; one nanosecond is the strictest setting.
- **XML attribute names** — an element of a response carrying two
  attributes of one local name (whatever their prefixes), or a prefixed
  attribute named like a SAML or XML-DSig attribute, is refused: parsers
  disagree on such documents. No IdP is known to emit them.
- **Legacy browsers** that mishandle `SameSite=None` (Safari on iOS 12 and
  macOS 10.14, Chrome 51–66) drop the binding cookie: their logins fail
  with `ErrMissingBrowserBinding`.
- **Login CSRF by forced initiation** — `BeginLogin` cannot tell whether
  the user meant to start a login: the application must start logins only
  from a same-origin gesture (see
  [docs/saml-sp.md](docs/saml-sp.md#5-sessions-and-logout)).
- **Stores** — `saml/sp/storage/memory` never purges anything (development
  and tests only); `saml/sp/store/sql` ships no expiry job (its package
  documentation gives the cleanup statements). CI runs the stores on
  SQLite and miniredis; PostgreSQL 16, MySQL 8.0 and Redis 7.4 are covered
  by an opt-in suite (`internal/interop/saml/compose.yaml`).
- **SP key rollover with Keycloak** — a Keycloak SAML client keeps one SP
  signing certificate: `AdditionalSigningCertificates` cannot announce the
  next key there, and the client's certificate must be replaced when the
  SP switches.
- **Interoperability** — CI runs the SP against crewjam/saml's IdP and
  replays 15 pinned Keycloak responses (26.7.4 and 26.0.7). Live runs
  against Keycloak 26.7.4 and the browser suite (Chrome 154) are opt-in;
  no other IdP (AD FS, Entra ID, Okta, Shibboleth) and no other browser
  engine is tested. See
  [docs/saml-sp.md](docs/saml-sp.md#interoperability-evidence).

## Transports

- Only `net/http` and gRPC adapters are shipped. Other transports can be
  added downstream by implementing `security.Carrier`.

## Sessions

- The session module is stateless: the whole session lives in an encrypted
  cookie, there is no server-side session store. This covers the common
  case without server state, but a session cannot be revoked server-side
  before its cookie expires. A server-side store (Redis/SQL) is not shipped.

## Logging

- **What `fmt` cannot redact** — the types that hold secrets
  (`oidcclient.Config` and `*Client`, `oauth2.DefaultClient`, the `jwtsec`
  keys, signers and key sets, `session.Codec`…) print redacted with every
  `fmt` verb and in `slog` output, but fmt prints some values without
  calling any of their methods: `%p` of a value that is not a pointer, a
  value held in an unexported field of your own types, and — for the verbs
  a pointer does not take (`%s`, `%q`…) — what a nested pointer points to.
  Log these types directly or through exported fields, with `%v`.
- **JSON** — `slog`'s JSON handler calls `LogValue` for attribute values
  only: a value nested in another one (a struct field, a map) is encoded
  with `encoding/json`. `oidcclient.Config`, `AuthRequest` and `Callback`
  encode without their secrets, but `oidcclient.Identity` and `Tokens`
  encode their tokens — deliberately, so that applications can persist them
  — and `UserInfo` its claims: log these as attributes of their own. Other
  reflection-based encoders (`encoding/gob`, `encoding/xml`, YAML) write
  every exported field, an `AuthRequest`'s binding secret included.
- **Credentials and tokens in flight are not redacted yet** — `basic` and
  `bearer` authentications print the password (before authentication) and
  the bearer token they carry, and the `oauth2` records
  (`AuthorizationCode`, `AccessToken`, `RefreshToken`, the `GrantResponse`
  holding them) the raw code and tokens they carry during issuance: never
  log them.

## Tooling

- The tests use mockery mocks generated by `make generate` and never
  committed. A published module's tests (from its module zip: `go test all`,
  `go vet` from the module cache, distribution builds) only compile from a
  repository checkout after `make generate`; the library code builds without
  them.

## Not planned

- **`HTTPDigestFilter` (RFC 7616)** — Digest auth is effectively dead; it
  will not be implemented unless a concrete need surfaces.
- **LDAP / API-key authenticators** — easy to add downstream as
  `security.Authenticator` implementations; not shipped in the core library.
- **DPoP (RFC 9449)** and **JWE** — out of scope for the initial release;
  candidates for a later minor version.
