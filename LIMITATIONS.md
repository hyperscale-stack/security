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
