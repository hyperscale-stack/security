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
