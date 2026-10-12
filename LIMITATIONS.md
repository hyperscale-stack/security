# Known limitations

The v2 stack covers HTTP and gRPC transports, HTTP Basic / Bearer schemes,
password hashing, JWT, OAuth2 (issuer + resource server), production
storage backends, and stateless cookie sessions. This document tracks what
is **not** yet covered. Remaining items are tracked as GitHub issues rather
than future refactor phases.

## OAuth2 server

- **`private_key_jwt` client authentication (RFC 7523)** — not implemented.
  `client_secret_basic`, `client_secret_post`, and `none` are.
- **RFC 6749 §4.4 is not enforced yet** — the `client_credentials` grant
  "MUST only be used by confidential clients", but it is not refused to
  public clients (authenticated with `none`), and an empty
  `GrantTypeValues` allows every grant: restrict `GrantTypeValues` for
  public clients.
- **`/.well-known/jwks.json` endpoint** — not exposed. JWKS publication
  depends on a server-side public-key store; the `jwtsec` module already
  provides the building blocks (`NewStaticJWKS`).
- **Offline JWT access tokens are not revocable** — a token-family
  revocation takes effect in the store, not at resource servers verifying
  JWT access tokens offline (`jwtsec.BearerVerifier`): the RFC 9068 payload
  carries no family or `jti` claim to deny-list, so such a token stays
  valid until it expires. Keep their lifetime short, or validate against
  the store. See
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
- **No RFC 9207 `iss` authorization-response parameter** — `/authorize` does
  not tell the client which issuer answered. A client talking to several
  authorization servers (or to several realms of one `IssuerResolver`) must
  defend against mix-up attacks with a distinct redirect URI per issuer
  (RFC 9700 §4.4.2.2) until it is added; the issuer is already resolved
  before any redirected answer, so adding it is local to `/authorize`.
- **`/introspect` returns no `iss`** — the token's issuer reaches an
  `IntrospectionPolicy` (`IntrospectedToken.Issuer`), not the response body.
- **Duplicated request parameters are not refused** — `/authorize` and
  `/token` read the first value of a repeated parameter, while RFC 6749 §3.1
  says request parameters MUST NOT be included more than once. An
  `oauth2.Extension` sees every value in `r.Form` and can refuse its own.
- **The `nonce` parameter is not bounded by the core** — `/authorize` records
  it as sent; an OpenID provider extension bounds it.
- **`oauth2.Extension` scope** — it extends the `authorization_code` and
  `refresh_token` exchanges; the implicit flow runs its authorization hooks
  and records their context, but its fragment members are fixed (RFC 6749
  §4.2.2), and the `client_credentials` and `password` grants never call it.
  Response modes: `query` for the code flow — the only one the metadata
  advertises — and `fragment` only for an enabled implicit flow; `form_post`
  is refused.

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
- **Private networks** need an explicit `AllowedPrefixes` exemption, and
  only the well-known NAT64 prefix (`64:ff9b::/96`) is translated; a
  network-specific NAT64 prefix is refused like any non-global IPv6
  address.

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
