# Known limitations

The v2 stack covers HTTP and gRPC transports, HTTP Basic / Bearer schemes,
password hashing, JWT, OAuth2 (issuer + resource server), OpenID Connect
(provider and relying party), a SAML 2.0 Service Provider, production
storage backends, and stateless cookie sessions. This document tracks what is
**not** yet covered. Remaining items are tracked as GitHub issues rather than
future refactor phases.

## OAuth2 server

- **`private_key_jwt` client authentication (RFC 7523)** — not implemented.
  `client_secret_basic`, `client_secret_post`, and `none` are.
- **RFC 6749 §4.4 is not enforced yet** — the `client_credentials` grant
  "MUST only be used by confidential clients", but it is not refused to
  public clients (authenticated with `none`), and an empty
  `GrantTypeValues` allows every grant: restrict `GrantTypeValues` for
  public clients.
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
  `consumed`, #83's `issuer` and `extension_data`) are added with the
  statements MIGRATION.md lists, through your migration tool.
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
- **Duplicated request parameters are not refused** — `/authorize` and
  `/token` read the first value of a repeated parameter, while RFC 6749 §3.1
  says request parameters MUST NOT be included more than once. An
  `oauth2.Extension` sees every value in `r.Form` and can refuse its own:
  `oidc/provider` refuses them in OpenID authentication requests.
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
  without `redirect_uri`, or with a repeated one, is refused with a bare
  400 (Core §3.1.2.1) once the oauth2 core accepted it; an error of the
  core's own checks (response type, scope, PKCE) comes first and is
  redirected, as for any OAuth 2.0 request, to the client's sole registered
  redirect URI or to the first, registered, occurrence of a repeated one.
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
- **No certification** — the OpenID Foundation conformance suite is run
  separately (#86); no certification is claimed.

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
- **Client authentication** — `private_key_jwt`, `client_secret_jwt` and
  mTLS; DPoP. `client_secret_basic`, `client_secret_post` and `none` are
  supported.
- **Token lifecycle** — no refresh-token helper (refresh tokens are
  returned to the application, which redeems them itself), no logout
  (RP-initiated, front- or back-channel), no dynamic client registration.
- **Claims** — aggregated and distributed claims are left unresolved in
  `Identity.Claims`.
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
- **Transaction stores** — the integrity MAC of a transaction is keyed by
  its binding secret, which the user agent of the login holds: an attacker
  with write access to the store can still relax the `max_age` and
  `acr_values` checks of logins it runs itself (a server-held key would
  close this; not implemented). Protect the store's integrity when relying
  on step-up authentication. `oidc/client/storage/memory` keeps transactions
  in the process: use the SQL or Redis store when several instances serve
  callbacks. `oidc/client/store/sql` ships `PurgeExpired`, a single
  unbatched `DELETE` the operator schedules (index `expires_at`, see its
  package documentation), and its PostgreSQL and MySQL guarantees are not
  exercised in CI (SQLite only). On Redis, a consumption acknowledged by a
  primary that fails before replicating it can be lost in a failover,
  making the transaction consumable again: single use then rests on the
  provider's single-use authorization code and on the binding secret only
  the user agent holds. The browser test of the binding cookie
  (`internal/interop/oidcrp`, headless Chrome) is opt-in
  (`OIDC_BROWSER_TESTS=1`) and does not run in CI.

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
  role, and the verification of signed metadata: importing
  administrator-provided metadata is the act of trust. Network retrieval of
  IdP metadata is not shipped.
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
  inclusive C14N is never accepted.
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
- **Stores** — `saml/sp/storage/memory` never purges anything (development
  and tests only); `saml/sp/store/sql` ships no expiry job (its package
  documentation gives the cleanup statements) and is tested on SQLite only.
- **Interoperability** is tested against crewjam/saml's IdP, which signs
  with the library the SP verifies with, and against one pinned Keycloak
  26.0.7 response. Live runs against Keycloak and real browsers are tracked
  in #88.

## Transports

- Only `net/http` and gRPC adapters are shipped. Other transports can be
  added downstream by implementing `security.Carrier`.

## Sessions

- The session module is stateless: the whole session lives in an encrypted
  cookie, there is no server-side session store. This covers the common
  case without server state, but a session cannot be revoked server-side
  before its cookie expires. A server-side store (Redis/SQL) is not shipped.

## Tooling

- `.mockery.yaml` targets mockery v3 syntax while the tool pinned in the
  module is still v2. `make generate` therefore fails until the config and
  the tool pin are reconciled; CI skips `make generate`. No module relies on
  generated mocks — every test uses hand-written fakes — so this is not on
  the critical path.

## Not planned

- **`HTTPDigestFilter` (RFC 7616)** — Digest auth is effectively dead; it
  will not be implemented unless a concrete need surfaces.
- **LDAP / API-key authenticators** — easy to add downstream as
  `security.Authenticator` implementations; not shipped in the core library.
- **DPoP (RFC 9449)** and **JWE** — out of scope for the initial release;
  candidates for a later minor version.
