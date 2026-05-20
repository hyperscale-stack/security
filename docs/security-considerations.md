# Security considerations

This document records the security posture of the library: the defaults it
ships, the attacks it defends against, and the choices left to the operator.

## Password hashing

Two `password.Hasher` implementations are shipped:

- **bcrypt** — `NewBCryptHasher(cost)`. Constant-time comparison is provided
  by `golang.org/x/crypto/bcrypt`.
- **Argon2id** — `NewArgon2idHasher(params)`. The default profile
  (`DefaultArgon2idParams`) follows RFC 9106 §4 / OWASP 2024: memory 19 MiB,
  time 2, parallelism 1, 32-byte key, 16-byte salt.

`NeedsRehash` lets a login flow transparently upgrade a stored hash when the
operator raises the cost factor. Call it after a successful `Verify` and
re-hash if it returns true.

A plain mismatch returns `(false, nil)` — only malformed input or context
cancellation produces an error. Never store or log the cleartext password.

## Account enumeration

`basic.Authenticator` collapses every failure — unknown user, loader error,
disabled/locked/expired account, password mismatch — into a single
`security.ErrInvalidCredentials` at the client boundary. The detailed cause
stays in the wrapped error chain for server-side telemetry only. Do not
mirror the detailed cause in the HTTP/gRPC response.

## JWT

`jwtsec` defends against the two classic JWT attacks:

- **`alg=none`** — rejected. The verifier parses with an explicit algorithm
  allowlist, so an unsigned token never reaches key resolution.
- **Algorithm confusion** (HS256 forged with an RSA public key) — the
  default allowlist is asymmetric only: `RS256/384/512`, `PS256/384/512`,
  `ES256/384/512`, `EdDSA`. HMAC algorithms are **not** allowed by default;
  enable them with `WithAllowedAlgorithms` only when both ends share a
  symmetric secret and you understand the trade-off.

The verifier also validates `iss`, `aud`, `exp`, `nbf`, and `iat` with a
configurable clock skew, and resolves keys by `kid` against a JWKS provider
(static or cached-remote).

## OAuth2

- **PKCE** — `authorization_code` requires PKCE. `S256` is the only method
  allowed under `Profile21Draft`; `plain` is accepted (with a warning) only
  under the looser profiles.
- **Refresh-token rotation** — every refresh issues a new token and
  invalidates the old one. Re-use of an already-rotated token is treated as
  theft: the whole token family is revoked (`RotateRefreshToken` returns
  `ErrRefreshTokenReused`).
- **Token storage** — access tokens, refresh tokens, and authorization
  codes are stored **hashed only**. The store never sees cleartext, so a
  database compromise does not yield usable tokens. Hashing uses an
  HMAC-SHA-256 keyed with a server-side pepper.
- **Atomic single-use** — `ConsumeAuthorizationCode` and
  `RotateRefreshToken` are atomic in every `Storage` implementation (SQL
  transactions, Redis Lua scripts). Concurrent use of the same code/token
  yields exactly one winner; the conformance suite verifies this under
  100-goroutine races.
- **Profiles** — `Profile20BCP` (the default) follows the OAuth 2.0
  Security BCP: it refuses the `implicit` grant. `Profile21Draft`
  additionally refuses the `password` grant. Legacy grants are opt-in and
  refused outright under the stricter profile.
- **Client authentication** — `client_secret_basic` / `client_secret_post`
  compare secrets in constant time. Public clients use `none` and MUST use
  PKCE.

## Sessions

`session` issues a **stateless encrypted cookie** — there is no server-side
session store to compromise or scale.

- **Confidentiality + integrity** — the cookie payload is sealed with
  AES-256-GCM (AEAD): tampering fails decryption, it is not merely detected.
- **Key rotation** — the `Codec` accepts an ordered key list. New cookies
  are sealed with the first key; decryption is attempted against every key,
  so a key can be retired gracefully.
- **Cookie attributes** — defaults are conservative: `Secure=true`,
  `HttpOnly=true`, `SameSite=Lax`. Disable `Secure` only for local plain-HTTP
  development.
- **Session fixation** — `Manager.Rotate` mints a fresh session ID; call it
  immediately after a privilege change (login). The ID never appears raw in
  a span — only a SHA-256 fingerprint.
- **CSRF** — the synchronizer-token helper (`CSRFToken` / `VerifyCSRF`)
  compares tokens in constant time. The session cookie being `HttpOnly`
  keeps the token out of reach of XSS.
- **Size** — the whole session is JSON-encoded into the cookie; browsers
  cap a cookie near 4 KiB. Keep `Values` small.

## Transport error mapping

Error mappers return terse, code-first responses. HTTP emits a status code
plus a `WWW-Authenticate` challenge; gRPC emits a `codes.Code`. Clients are
expected to branch on the code, not parse the message — the message never
leaks why authentication failed.

## Observability

No secret is ever placed on a span attribute or log line. See
[observability.md](observability.md) for the secrets policy and the full
span catalog.

## Operator checklist

- [ ] Pick a password hasher and review its cost against current hardware.
- [ ] Rotate JWT signing keys; expose them through a JWKS endpoint.
- [ ] Keep the JWT allowlist asymmetric unless you truly need HMAC.
- [ ] Provide a server-side pepper for OAuth2 token hashing.
- [ ] Use `Profile20BCP` or stricter; do not enable `implicit`/`password`
      grants without a documented reason.
- [ ] Serve over HTTPS so `Secure` cookies and bearer tokens are protected.
- [ ] Supply at least two session keys so rotation is possible without
      invalidating live sessions.
- [ ] Install an OpenTelemetry `TracerProvider` to collect the spans.
