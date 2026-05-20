# Migrating from v0

The v0 stack (`authentication/`, `authorization/`, the in-tree `password`
package, and `authentication/provider/oauth2`) was removed during the
refactor. This guide maps the old API to the v2 stack. For the workspace
layout and the new module list see [../MIGRATION.md](../MIGRATION.md).

## Concept mapping

| v0                                              | v2                                                       |
| ----------------------------------------------- | --------------------------------------------------------- |
| `authentication.Credential` (mutable, `any`)    | `security.Authentication` (immutable interface)           |
| `authentication.Filter` / `OnFilter`            | `security.Extractor` — `Extract(ctx, Carrier)`            |
| `authentication.Provider` / `Authenticate`      | `security.Authenticator` — `Authenticate(ctx, Authentication)` |
| `authentication.Handler` (the filter loop)      | `security.Engine` + `httpsec.Middleware`                  |
| `authorization.Option` checks                   | `voter.*` + `security.AccessDecisionManager`              |
| `password.BCryptHasher`                         | `password.Hasher` (`NewBCryptHasher` / `NewArgon2idHasher`) |
| `NewOAuth2AuthenticationProvider`               | `oauth2.Server` (issuer) + `bearer`/`jwtsec` (resource server) |

## Authentication is now immutable

v0 credentials were a mutable bag mutated in place by each filter. v2
`Authentication` is a read-only interface; an authenticator returns a *new*
value rather than mutating its input:

```go
// v2
func (a *Authenticator) Authenticate(ctx context.Context, auth security.Authentication) (security.Authentication, error) {
    // …validate…
    return in.WithAuthenticated(user, authorities), nil // new value
}
```

## Context is propagated everywhere

Every runtime operation now takes `context.Context` as its first argument —
`Extract`, `Authenticate`, `Hasher.Hash`/`Verify`, `UserLoader.Load`,
`TokenVerifier.Verify`. Thread the request context through; do not use
`context.Background()` on the request path.

## The Handler loop bug is gone

v0's `Handler` kept iterating filters after a successful authentication and
silently swallowed provider errors. v2 replaces it with:

- `security.Manager` — first-success-wins, then stops; all-fail produces an
  aggregated error reachable via `errors.Is`.
- `security.Engine` — runs extractors, calls the `Manager`, stores the
  result in the context.
- `httpsec.Middleware` / `grpcsec` interceptors — wire the `Engine` into a
  transport and map failures to status codes.

## Password verification reports errors

v0's `Verify` returned a bare `bool`, conflating "wrong password" with
"malformed hash". v2:

```go
ok, err := hasher.Verify(ctx, encodedHash, password)
// err != nil  -> malformed hash / unknown algorithm / cancelled
// err == nil  -> ok tells you whether the password matched
```

Call `hasher.NeedsRehash(encodedHash)` after a successful verify to upgrade
stored hashes when you raise the cost factor.

## Authorization: from option checks to voters

Replace ad-hoc role checks with attributes, voters, and an
`AccessDecisionManager`:

```go
adm := security.NewAffirmativeDecisionManager(voter.HasRole("ADMIN"))
mux.Handle("/admin", httpsec.Authorize(adm, security.Role("ADMIN"))(adminHandler))
```

## OAuth2: provider split into issuer and resource server

v0's `NewOAuth2AuthenticationProvider` mixed token issuance and token
validation. v2 separates them:

- **Authorization server** — `oauth2.NewServer(cfg)` exposes
  `TokenHandler`, `RevokeHandler`, `IntrospectHandler`, `MetadataHandler`.
- **Resource server** — validate incoming bearer tokens with `bearer` +
  a `TokenVerifier` (`jwtsec` for JWT access tokens, or introspection).

See [examples/oauth2](../examples/oauth2) for both halves wired together,
and the [examples/](../examples) directory for the other per-scenario demos.

## Transport imports

The v0 example imported `gorilla/mux`. v2 examples use the standard
`net/http.ServeMux` — no third-party router is required, and none is a
dependency of any module.
