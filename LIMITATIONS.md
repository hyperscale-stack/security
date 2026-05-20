# Known limitations (as of Phase 7e)

The legacy MVP (`authentication/`, `authorization/`, the old `password/`
package and the old `oauth2` provider) has been removed. This document
tracks what the v2 stack does **not** yet cover, mapped to the phase that
will address it.

## OAuth2 server

- `/oauth2/authorize` (authorization-code issuance + consent flow) is not
  implemented. The /token endpoint already covers `client_credentials` and
  `refresh_token` end-to-end; `authorization_code` works at the grant level
  (see `oauth2/grant`) but no HTTP endpoint mints the code yet.
  *Follow-up slice of Phase 7.*
- `private_key_jwt` client authentication (RFC 7523) is not implemented;
  `client_secret_basic`, `client_secret_post` and `none` are.
  *Follow-up slice of Phase 7.*
- No `/.well-known/jwks.json` endpoint — it depends on a server-side public
  key store. *Follow-up slice of Phase 7.*

## Production storage

- The only `oauth2.Storage` implementation is the in-memory store
  (`oauth2/storage/memory`); it loses all state on restart. Production SQL
  and Redis stores with real atomicity (transactions / Lua scripts) and a
  shared conformance test suite are *Phase 8*.

## Transports

- No gRPC adapter yet — the `grpc/` module is an empty placeholder.
  *Phase 9.*

## Sessions

- No cookie-session module — the `session/` module is an empty placeholder.
  *Phase 10.*

## Examples & docs

- Only `example/oauth2` is wired to the v2 stack. The per-use-case examples
  (basic-http, bearer-jwt, grpc-bearer, session-web, multi-tenant…) and the
  `docs/` set (core concepts, observability catalog, migration guide) are
  *Phase 11*.

## Tooling

- `.mockery.yaml` is being migrated to mockery v3 syntax (`pkgname`,
  `template`, `template-data`) while the tool pinned in `go.mod` is still
  v2.53.5. `make generate` therefore fails until the config and the tool
  pin are reconciled. CI skips `make generate`. No module currently relies
  on generated mocks — every test uses hand-written fakes — so this is not
  on the critical path. *To resolve before the v1 tag (Phase 11).*

## Not planned

- `HTTPDigestFilter` (RFC 7616) — Digest auth is effectively dead in 2026;
  it will not be implemented unless a concrete need surfaces.
- LDAP / API-key authenticators — easy to add downstream as `security.Authenticator`
  implementations; not shipped in the core library.
