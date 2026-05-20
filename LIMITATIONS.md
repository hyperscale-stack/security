# Known limitations

The v2 stack covers HTTP and gRPC transports, HTTP Basic / Bearer schemes,
password hashing, JWT, OAuth2 (issuer + resource server), production
storage backends, and stateless cookie sessions. This document tracks what
is **not** yet covered. Remaining items are tracked as GitHub issues rather
than future refactor phases.

## OAuth2 server

- **`/authorize` endpoint** — the authorization-code *grant* is implemented
  and exercised end-to-end (see `oauth2/grant`), but no HTTP endpoint mints
  the code through a browser redirect + consent flow. `client_credentials`
  and `refresh_token` are fully served by `TokenHandler`.
- **`private_key_jwt` client authentication (RFC 7523)** — not implemented.
  `client_secret_basic`, `client_secret_post`, and `none` are.
- **`/.well-known/jwks.json` endpoint** — not exposed. JWKS publication
  depends on a server-side public-key store; the `jwtsec` module already
  provides the building blocks (`NewStaticJWKS`).

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
