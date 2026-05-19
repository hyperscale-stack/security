# Known limitations (as of Phase 0 stabilisation)

This document captures the gaps of the current MVP that are not yet addressed.
Each item is scheduled for one of the upcoming phases of the architecture
refactor (see [ARCHITECTURE_REPORT.md](ARCHITECTURE_REPORT.md) and the plan
file referenced there).

## Transport coupling

- The core types (`authentication.Filter`, `authentication.Provider`) are bound
  to `*http.Request`. No gRPC support yet. *Addressed in Phase 2 (Carrier) and
  Phase 9 (grpcsec).*

## Credential model

- `credential.Credential` uses `interface{}` for principal and credentials with
  no type-safe helpers. *Addressed in Phase 2 (`security.Authentication`).*
- `Credential` is mutable in place via `SetAuthenticated`/`SetUser`. *Replaced
  by an immutable model in Phase 2.*

## Context propagation

- `Filter.OnFilter`, `Provider.Authenticate`, `password.Hasher.Hash/Verify`,
  `dao.UserProvider.LoadUserByUsername`, `oauth2.*.Load*` do not take a
  `context.Context`. *Addressed in Phase 2/4 with new interfaces.*

## Time injection

- `oauth2.AccessInfo.IsExpired()` and `oauth2.AuthorizeInfo.IsExpired()` call
  `time.Now()` directly. The additive `IsExpiredAt(t time.Time)` is available
  for deterministic tests, but the `Clock` interface is not yet plumbed
  through the OAuth2 provider. *Phase 7.*

## Password hashing

- `password.Hasher.Verify` returns `bool` instead of `(bool, error)`, swallowing
  malformed-hash errors. *Phase 4: new signature with ctx + error.*
- No `NeedsRehash`, no Argon2id implementation. *Phase 4.*
- `NewBCryptHasher(cost)` does not validate `cost` (a 0 will fail at runtime).
  *Phase 4.*

## OAuth2 server

- No `/authorize`, `/token`, `/revoke`, `/introspect`, `/.well-known/...`
  endpoints. The provider only validates HTTP Basic client credentials and
  bearer access tokens; it does not *issue* them. *Phase 7.*
- No PKCE verifier (S256 / plain).
- No refresh-token rotation, no reuse detection.
- No introspection (RFC 7662) or revocation (RFC 7009).
- Tokens are stored verbatim in `InMemoryStorage` (no hashing of access /
  refresh tokens / authorization codes). *Phase 7.*
- `OAuth2AuthenticationProvider.IsSupported` advertises support for
  `UsernamePasswordCredential` and treats it as client credentials. This will
  be split into a dedicated `ClientCredential` type in Phase 7.
- `StorageProvider` operations (`ConsumeAuthorizationCode`,
  `RotateRefreshToken`) are not atomic. *Phase 7/8.*
- `InMemoryStorage` is the only implementation; no production SQL/Redis store.
  *Phase 8.*

## Authentication providers

- No JWT provider, no LDAP provider, no session/cookie provider, no API key
  provider. *Phases 4 (basic/bearer), 6 (jwt), 10 (session).*
- No `HTTPDigestFilter`. *Probably never (RFC 7616 is rare in 2026); to be
  decided.*

## Authorization

- Only `HasRole(role string)` is provided. No `HasAnyRole`, `HasScope`,
  `HasAuthority`, `HasPermission`, `Authenticated`, `Anonymous`, composition
  voters (`And`/`Or`/`Not`). *Phase 5.*
- The `Option func(Credential) bool` signature has no access to the request,
  no error channel, no asynchronous I/O. *Replaced by `Voter` /
  `AccessDecisionManager` in Phase 5.*

## Errors

- Sentinels (`ErrInvalidCredentials`, `ErrClientSecretMismatch`,
  `ErrTokenExpired`, `ErrTokenNotFound`, `ErrUnsupportedCredential`) exist at
  the root since Phase 0, but most internal packages still expose their own
  sentinels (`oauth2.ErrAccessNotFound`, `dao.ErrBadPassword`, …) that are not
  yet wrapped through the root ones. *Progressive in Phases 2-7.*
- The HTTP response body is the hard-coded string `"Access denied"`. No
  `ErrorMapper`, no JSON error format, no `WWW-Authenticate` challenge.
  *Phase 3 (httpsec.ErrorMapper).*

## Observability

- No OpenTelemetry spans yet. *Phase 2 introduces tracing in the core; each
  subsequent phase adds spans in its module.*

## Configuration / DX

- No top-level `Engine` / `Manager` builder. Users have to manually chain
  `FilterHandler` + `Handler` + `AuthorizeHandler`. *Phase 2 introduces
  `security.NewEngine(...)`.*
- The OAuth2 provider constructor takes 6 storage parameters of similar types,
  which is error-prone. *Phase 7 replaces it with `oauth2.NewServer(cfg)`.*

## Multi-tenancy

- A single global issuer / single client store. *Phase 7 introduces
  `IssuerResolver`.*
