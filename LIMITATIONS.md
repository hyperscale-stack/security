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
  none, although its RFC 8414 metadata advertises `jwks_uri` (the issuer
  followed by `/.well-known/jwks.json`): mount the
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
  `redirect_uri_omitted`, the refresh tokens' `family_issued_at`) are added
  with the statements MIGRATION.md lists, through your migration tool.
- **A leaked code can be burned** — codes are consumed before they are
  validated, so a party holding a code (but not its client's credentials or
  PKCE verifier) can make the legitimate exchange fail with
  `invalid_grant`; it obtains nothing. A deliberate trade-off, see
  [docs/security-considerations.md](docs/security-considerations.md).
- **Every registered client is trusted to receive error redirects** — an
  error `/authorize` detects before the resource owner authenticated is
  redirected to the client's registered redirect URI unless
  `AuthorizeConfig.TrustedRedirect` says the client is not trusted (RFC
  9700 §4.11.2); set it when clients are registered by third parties. An
  explicit denial after authentication (`access_denied`) is redirected to
  every client — RFC 9700 §4.11.2's second attack: a `ConsentFunc` may warn
  the resource owner about a client it does not trust.
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
- **`/introspect` returns no `iss`** — an active token is always of the
  issuer the request resolved to; the token's issuer reaches an
  `IntrospectionPolicy` (`IntrospectedToken.Issuer`), not the response body.
- **`oauth2.Extension` scope** — it extends the `authorization_code` and
  `refresh_token` exchanges; the implicit flow runs its authorization hooks
  and records their context, but its fragment members are fixed (RFC 6749
  §4.2.2), and the `client_credentials` and `password` grants never call it.
  Response modes: `query` for the code flow, and `fragment` only for an
  enabled implicit flow — which the metadata advertises once an
  `AuthorizeHandler` enabling it is built; `form_post` is refused.

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
- **Access-token audience** — the provider refuses an access token whose
  audience is the requesting client's ID (it would be an ID Token's), but
  does not compare it with the other clients' IDs: keep every
  `IssuerResolver` audience apart from all client IDs.
- **Claim-name aliasing beyond case variants** — the provider compares claim
  names ignoring case (simple and full case mappings), the diacritics
  lodash's `camelCase` strips from Latin letters, and every character but
  letters, decimal digits and `#`; a relying party comparing them under
  compatibility normalization (NFKC: fullwidth `ｓｕｂ`), stripping other
  diacritics (`ṡ`, beyond Latin-1 and Latin Extended-A), under
  locale-sensitive collation, or reading confusable letters (Cyrillic `ѕ`)
  as Latin ones is not covered. An application claim missing from
  `Config.ClaimsSupported` is released under another spelling when requested
  alone, and dropped together with such a variant — an end-user can suppress
  it: declare every claim relying parties decide on.
- **Account checks of plain OAuth 2.0 grants** — the `ClaimsSource` stops an
  OpenID grant whose end-user is gone (`ErrUnknownSubject`), but a grant
  without `openid` carries no provider context and is not checked: revoke
  the end-user's token families too.
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

## JWT (`jwtsec`)

- **Token strings are not unique** — an ECDSA signature has a second valid
  form (s and n − s): the verifier accepts both, since refusing the "high"
  one would refuse half of the legitimate tokens of other signers. Never key
  a cache, replay check or deny-list on the token string; use `jti`.
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
  token without `kid` is verified against a single-key set only.
- **Remote JWK Set policy** — the TTL is configurable (`WithCacheTTL`); the
  minimum refresh interval (10 s), the back-off cap (5 minutes), the
  maximum staleness (24 h), the 100-key and 2048–8192-bit RSA bounds, the
  10 s and 1 MiB fetch bounds are not. An RSA key published without `alg`
  verifies RS256 when the verifier allows it, otherwise the verifier's only
  RSA algorithm, otherwise nothing: publish `alg` on RSA keys signing
  PS256/384/512. A JWK Set URL redirecting to another origin cannot be
  used, whatever `MaxRedirects`: configure the final URL.
- **No JWS extension, nested JWT or JWE** — tokens whose header uses `crit`
  or `b64` are refused, and a nested JWT (`cty: JWT`, RFC 7519 §7.2 step 8)
  is refused because its payload is not a claims object.
- **Size bound** — tokens over 16 KiB are refused by default
  (`WithMaxTokenSize` on a `Verifier`); `VerifySignature` always applies
  the default bound.

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
  (refresh its metadata) before the IdP signs with it. Without `KeyInfo` —
  or with a `KeyInfo` that carries no certificate, which counts as absent —
  only the three most recent valid certificates of the connection are
  tried, the one that verified its last such signature first. Validity is
  checked at `now − ClockSkew`, so a certificate whose validity starts at
  the rollover is accepted only `ClockSkew` later.
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
- **Basic credentials are not NFC-normalized yet** — a Basic challenge
  advertises `charset="UTF-8"`, which per RFC 7617 §2.1 also says the server
  expects the user-id and password in Unicode Normalization Form C; `basic`
  checks them as received.

## HTTP Basic

- **No rate limiter or account lockout is shipped** — NIST SP 800-63B-4
  §3.2.2 requires verifiers to limit failed attempts: do it at the edge or
  in an `Authenticator` wrapper. The `Authenticator` only caps the number
  of concurrent verifications (`runtime.GOMAXPROCS(0)` by default).
- **Timing equalization residuals** — every attempt costs one verification,
  but a stored hash made with other parameters than the hasher's costs
  another time until it is re-hashed (`PasswordRehasher`), and the
  `UserLoader`'s own latency (a cache hit for a known user) is outside the
  library's control.

## Passwords

- **No Unicode normalization** — the hashers hash a password's bytes as
  given, so a password typed in NFD on one device and NFC on another does
  not verify. NIST SP 800-63B-4 §3.1.1.2 says verifiers SHOULD apply NFC:
  wrap the hasher in the decorator shown in the `password` package
  documentation (it needs `golang.org/x/text`, which the module does not
  depend on).
- **bcrypt: 72 bytes** — longer passwords are refused (`ErrPasswordTooLong`),
  which caps passwords of multi-byte characters below the 64 characters
  SP 800-63B-4 asks verifiers to permit. Hashes imported from an
  implementation that truncated silently need the migration wrapper of
  MIGRATION.md. Prefer Argon2id.

## Sessions

- The session module is stateless: the whole session lives in an encrypted
  cookie, there is no server-side session store. This covers the common
  case without server state, but a session cannot be revoked server-side
  before its cookie expires. A server-side store (Redis/SQL) is not shipped.
- The session cookie is read through `httpsec.Carrier` (its
  `CookiesNamed` accessor). The `grpcsec` and `connectrpcsec` carriers expose
  no cookies: a cookie session does not authenticate gRPC or ConnectRPC
  calls (Connect-Web clients included).

## Logging

- **What `fmt` cannot redact** — the types that hold secrets
  (`oidcclient.Config` and `*Client`, `oauth2.DefaultClient`, the `jwtsec`
  keys, signers and key sets, `session.Codec`…) print redacted with every
  `fmt` verb and in `slog` output — as do the `grpcsec` and
  `connectrpcsec` carriers, which print metadata key counts only — but fmt
  prints some values without
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
