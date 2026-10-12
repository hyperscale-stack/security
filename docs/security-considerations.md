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

- **PKCE** — `authorization_code` requires PKCE under `Profile20BCP` and
  `Profile21Draft`; under `Profile20` it is optional unless
  `grant.Config.RequirePKCE` is set. `S256` is the only method accepted
  under BCP / 2.1; `plain` is tolerated only under `Profile20`. Both ends
  enforce the RFC 7636 syntax: `/authorize` answers `invalid_request` to a
  `code_challenge` that is not 43–128 unreserved characters (`plain`) or
  not the unpadded base64url SHA-256 digest (`S256`), and, for a code
  bound to a `code_challenge`, `/token` answers `invalid_grant` to a
  `code_verifier` that is not 43–128 unreserved characters. The code is
  consumed whether the verifier is malformed or wrong. Well-formed
  verifiers are compared in constant time.
- **Refresh-token rotation** — mandatory under `Profile20BCP` (the default)
  and `Profile21Draft`, whatever `grant.Config.RotateRefreshTokens` says:
  every refresh exchange consumes the presented token and issues a new one
  in the same family (RFC 9700 §4.14.2). The profiles apply it to every
  client, stricter than RFC 9700 §2.2.2, which requires rotation — or
  sender-constrained refresh tokens, which this library does not issue — for
  public clients only. Under these profiles — and under `Profile20` when
  `RotateRefreshTokens` is set — `NewServer` refuses a `refresh_token` grant
  without a `RefreshTokens` generator, and the grant itself fails with
  `server_error` before minting anything when it cannot rotate. Re-use of an
  already-rotated token is treated as theft: the whole family is revoked
  (`ErrRefreshTokenReused`), with the guarantees described under
  [Token-family revocation](#token-family-revocation-storage-guarantees).
  Clients MUST keep the refresh token returned by each exchange (RFC 6749
  §6) and must not refresh concurrently with the same token, or they lose
  the family. Under `Profile20` rotation is opt-in (`RotateRefreshTokens`);
  without it a refresh token stays reusable until it expires, which RFC 9700
  §2.2.2 forbids for public clients.
- **Token storage** — access tokens, refresh tokens, and authorization
  codes are stored **hashed only** (SHA-256, via `oauth2.HashToken`). The
  store never sees cleartext, so a database compromise does not yield
  usable tokens. Tokens carry ≥ 128 bits of entropy, so the bare hash is
  preimage- and brute-force-resistant.
- **Atomic single-use** — `ConsumeAuthorizationCode` is atomic in every
  `Storage` implementation, and so are the token writes: `SaveTokenPair`
  and `RotateRefreshToken` persist a whole pair or nothing, gated by the
  token family (SQL transactions with row locks, Redis Lua scripts, a mutex
  in memory). Concurrent use of the same code or refresh token yields
  exactly one winner; the conformance suite checks it with 50 concurrent
  consumers of one code and 30 concurrent rotations of one token, and races
  revocations against rotation chains and issuance.
- **Authorization-code replay** — exchanging a consumed code is refused with
  `invalid_grant`, and the tokens its first exchange issued are revoked:
  access and refresh tokens, and every later rotation (RFC 6749 §4.1.2,
  §10.5; RFC 9700 §4.2.4). Only a replay that would itself have been
  accepted revokes: the code has not expired, and the client it was issued
  to presents it with the same `redirect_uri` and PKCE verifier and may
  still use `authorization_code` (OAuth 2.1 §4.1.3, §7.5.3). Anything else —
  another client, a missing or wrong verifier, an unknown code — is refused
  and revokes nothing: a public `client_id` is no secret, and revoking on
  any replay would let whoever holds a leaked code cut the client off. The
  grant derives the code's token family from the code before consuming it,
  so the link takes no storage and a replay racing the first exchange cannot
  leave its tokens active: one landing before that exchange persists its
  tokens makes it answer `invalid_grant` and issue nothing; one landing
  after revokes them. The first outcome holds while the store keeps the
  family's revoked record (`oauth2.FamilyRevocationRetention` at least),
  i.e. under the [deployment
  requirements](#token-family-revocation-storage-guarantees): an evicted
  Redis family key, or a SQL family row deleted before its `expires_at`,
  lets the in-flight exchange recreate the family active. Stores keep a
  consumed code, hashed and flagged, at least until it expires — Redis
  expires the key with the code, SQL rows stay until your cleanup, the
  memory store keeps them for good — so a replay is recognized for the
  code's lifetime (`AuthorizeConfig.CodeTTL`, 10 minutes by default); a
  later one is refused like any replay, and revokes nothing. A failed
  revocation reaches `grant.Config.OnError`, and the next proven replay
  retries it. A legitimate client retrying a lost response, or submitting a
  code twice, revokes its own tokens: a code MUST NOT be reused (RFC 6749
  §4.1.2). Access tokens validated offline are out of reach, see [Offline
  JWT access tokens](#offline-jwt-access-tokens).
- **Profiles** — `Profile20BCP` (the default) follows the OAuth 2.0
  Security BCP: it refuses the `implicit` grant. `Profile21Draft`
  additionally refuses the `password` grant. Legacy grants are opt-in and
  refused outright under the stricter profile.
- **Client authentication** — `client_secret_basic` / `client_secret_post`
  compare secrets in constant time and never accept an empty one. Basic
  form-decodes the user-id and password (RFC 6749 §2.3.1, Appendix B) after
  splitting them at the first colon, refuses an invalid escape as a
  malformed header, and answers an empty decoded password or a missing
  `client_id` with
  `401 invalid_client` before loading the client, the same answer whether
  or not the client exists; a form with an empty or absent `client_secret`
  is a `none` request, which only public clients may make. Custom
  `SecretMatcher`s MUST NOT match an empty secret; `DefaultClient` never
  matches an empty `Secret`. A public client has no secret: it
  authenticates with `none` (RFC 7591 §2) and MUST use PKCE. Register as
  public a client that cannot keep its credentials confidential (RFC 6749
  §2.1). `/introspect` answers `ClientConfidential` callers only: a public
  client (whatever the method, `none` included) or an untyped client gets
  `401 invalid_client`.
- **Token introspection** — RFC 7662 §4 requires the authorization server
  to authenticate the protected resources calling `/introspect`. A public
  client cannot authenticate: its `client_id` ships inside every copy of the
  app and RFC 6749 §2.2 forbids using it alone, and the authorization server
  MUST NOT rely on a public client's authentication — even with a secret —
  to identify it (RFC 6749 §2.3). Accepting one would let anyone read the
  validity and claims of a token they held — through `none`, or through
  Basic/Post with the client's registered secret — so `/introspect` refuses
  every caller that is not a confidential client. By default, any
  authenticated confidential client may then introspect any token.
  RFC 7662 §4 adds that protected resources SHOULD be specifically
  authorized, and that when a token can be used only at certain resource
  servers the authorization server MUST determine whether it can be used at
  the caller: that decision is `ServerConfig.IntrospectionPolicy`, which
  sees the authenticated caller and the token's metadata before anything is
  disclosed. Refuse refresh tokens to resource servers — they are meant for
  the client alone, and a resource server that ignores `token_type` could
  accept one as a bearer token. A withheld token and a failed policy answer
  the same bytes as an unknown token (`{"active":false}`), so the response
  discloses nothing (its latency may still differ); a policy failure is
  reported to `OnError`.
- **Issuer binding (realms)** — a subject is only meaningful within its
  issuer (OIDC Core §16.15). `/authorize` resolves the issuer of the request
  through the `IssuerResolver` right after the redirect URI is trusted;
  the code and every token record it, and the `authorization_code` and
  `refresh_token` grants refuse, with `invalid_grant`, a code or refresh
  token issued under another issuer than the one resolved at `/token` — so a
  client registered in several realms cannot carry an authorization across
  them. A refused refresh consumes nothing; a code replayed at another issuer
  revokes nothing, since it could not have redeemed the code — while a
  consumed refresh token presented at another issuer still revokes its
  family, the reuse check coming first (RFC 9700 §4.14.2). Records written
  before issuers were recorded fail closed. The resolver is the realm
  boundary: it must return the same issuer for `/authorize` and `/token` of
  a realm, and the `ConsentFunc` must authenticate the resource owner within
  `AuthorizeRequest.Issuer` — a session of another realm is no
  authentication. `IntrospectedToken.Issuer` lets an `IntrospectionPolicy`
  enforce the same boundary.
- **Authorization responses** — a `response_mode` other than the one the
  server answers in (`query` for the code flow, `fragment` for an enabled
  implicit flow) gets a bare 400, never redirected: the answer could not be
  encoded as the client expects (OIDC Core 1.0 incorporating errata set 2,
  §3.1.2.6). Redirected errors carry only the codes the authorization
  endpoint defines (RFC 6749 §4.1.2.1, OIDC Core §3.1.2.6); descriptions and
  `error_uri`s outside the RFC 6749 charset are left out, and the server's
  own descriptions never echo the request. An approval names its subject —
  non-empty, at most 255 bytes — or fails closed with `server_error`. A
  `ConsentFunc` refuses with a protocol code through `Consent.Refusal`; a
  `ConsentFunc` error is always a `server_error`. A refusal's description
  and URI travel in the client's URL — browser history, logs, `Referer` —
  so they must never carry personal data.
- **Mix-up defense (RFC 9207)** — every authorization response, code and
  implicit, success and redirected error, carries `iss`, the issuer the
  request resolved to, and the RFC 8414 metadata sets
  `authorization_response_iss_parameter_supported`: a client talking to
  several authorization servers — or to several realms of one
  `IssuerResolver` — compares it with the issuer it sent the request to and
  aborts on a mismatch (RFC 9700 §4.4.2.1), the defense RFC 9700 prefers to
  distinct redirect URIs. The issuer must therefore be a stable https URL
  without query or fragment (RFC 9207 §2). The one response without `iss` is
  the `server_error` answering an `IssuerResolver` failure.

### Protocol extensions

`ServerConfig.Extension` (`oauth2.Extension`) is trusted code — the
`oidc/provider` OpenID Provider, or the application's own — plugged into the
authorization-code flow. The server keeps every OAuth 2.0 check and runs it
first:

- **Bounded authority.** The extension only sees requests and exchanges the
  core accepted (client, redirect URI, response mode and type, scope, PKCE;
  client, issuer, redirect URI, verifier and expiry at `/token`). It can
  narrow a granted scope, never broaden it, and add an `id_token` member to
  a token response, never replace `access_token`, `token_type`,
  `expires_in`, `refresh_token` or `scope` — the response members are typed
  fields, not a map. Callbacks get read-only copies of the validated
  request: a `ConsentFunc` or extension hook that modifies its copy — the
  redirect URI, the state, the scope, the PKCE parameters, the nonce, the
  issuer, the client's identity — fails the authorization closed with
  `server_error` (`oauth2.ErrAuthorizeRequestModified`) rather than having
  its rewrite either honored or silently ignored; a grant narrows only
  through `Consent.Scope` and `ExtensionGrant.Scope`.
- **Grant context.** What `CompleteAuthorization` records (`ExtensionData`:
  at most 4096 bytes of UTF-8 without NUL, so every store keeps it
  byte-exact) is persisted with the code and copied onto every token derived
  from it; the stores refuse a refresh-token rotation that would change it,
  or the issuer. It can only be read back through the record its own code or
  refresh token designates: it cannot be substituted across clients,
  issuers, codes or token families, and a refresh never rewrites the
  authentication event it rests on (OIDC Core §12.2).
- **No partial success.** `ExtendTokenResponse` runs after the tokens are
  minted and before their single atomic write: when it fails nothing is
  persisted — a redeemed code stays consumed and a retry is a replay, a
  presented refresh token stays usable — and its `id_token` is dropped when
  the write fails afterwards. A replay of the code that revokes the family
  while the hook runs wins: the exchange in flight answers `invalid_grant`
  without its `id_token`. The hooks must therefore have no externally
  visible side effects.
- **Consumers of the context.** `AccessToken.ExtensionData` is empty for
  tokens no authorization precedes — `client_credentials`, whose `Subject` is
  a client ID, and the legacy `password` grant — and for records written
  before it existed. An endpoint serving end-user data from an access token
  (an OpenID Connect UserInfo endpoint) must require its extension's context
  and an `Issuer` equal to the issuer it serves, or it would serve the
  claims of whatever user shares a subject with a client ID.
- **Integration contracts.** `prompt=none` forbids any login or consent UI
  (OIDC Core §3.1.2.3): a raw `ConsentFunc` that renders a page runs before
  any hook can stop it, so an OpenID provider owns the `ConsentFunc` it
  hands the application. `CompleteAuthorization` binds the authentication
  event it records to `Consent.Subject` and refuses a trusted result it did
  not define. The hooks see the raw `/authorize` form — credentials
  included when a login form posts to it — and the raw access token: they
  must never log or persist either.

### Token-family revocation (storage guarantees)

Every access and refresh token issued from one authorization shares a token
family; `client_credentials` and implicit tokens belong to none. Revoking
the family is how the server answers a replayed refresh token (RFC 9700
§4.14.2, RFC 6749 §10.4) and how `/revoke` honours RFC 7009 §2.1, which asks
the server to invalidate the access tokens of a revoked refresh token's
grant (and allows revoking the refresh tokens of a revoked access token).
Every `Storage` keeps one authoritative state per family — active or
revoked — that issuance, rotation and lookups go through, so a revocation
never has to find the family's tokens:

- **Complete revocation.** A revocation is complete once
  `RevokeRefreshFamily` returned `nil`, or once a reuse was reported without
  `oauth2.ErrTokenFamilyRevocationFailed`. From then on no token of the
  family is usable through the store — access-token lookups fail with
  `invalid_grant`, refresh tokens read consumed — and every issuance or
  rotation into the family fails without persisting anything, including one
  that raced the revocation: it is ordered either before the revocation,
  which then covers its tokens, or after it, and is refused. A lookup
  running concurrently with the revocation may still answer "active".
- **Before the first token.** A family can be revoked before any of its
  tokens exists; the revocation is kept for at least
  `oauth2.FamilyRevocationRetention` (24 hours), and never for less than the
  lifetime of the family's tokens, so a late issuance is still refused.
- **Atomicity.** A failed issuance or rotation persists no token and
  consumes nothing: a failed exchange no longer leaves an access token
  behind.
- **Idempotence and isolation.** Revoking a revoked family changes nothing
  and succeeds; a revoked family never becomes active again. Revoking one
  family affects no other family and no token outside a family, and the
  empty family ID is refused.
- **Failure.** A revocation that cannot be recorded fails with
  `oauth2.ErrTokenFamilyRevocationFailed`, and its outcome may be unknown (a
  lost acknowledgement): treat the family as active and retry, which
  idempotence makes safe. `/revoke` then answers
  `503 temporarily_unavailable` — RFC 7009 §2.2.1: the client must assume
  the token still exists and may retry — since a `200` would tell the client
  the token can no longer be used (RFC 7009 §2.1). It revokes an access
  token's family before deleting the token, so a failed family revocation
  leaves everything in place for that retry. On the reuse path the store
  reports `ErrRefreshTokenReused` joined with the revocation failure, the
  `refresh_token` grant retries the revocation on a context detached from
  the request, and a second failure reaches `grant.Config.OnError`; the
  client gets `invalid_grant` either way.
- **Fail closed.** A token whose family state is missing — expired,
  evicted, deleted by a premature cleanup, or never written by a build
  predating token families — is treated as revoked. This protects lookups
  only: the next issuance into a family whose revoked state was lost records
  it active again and revives its tokens, so a revoked family's state must
  never be lost within its retention — no eviction, no early cleanup.
- **Lost responses look like theft.** When the response to a successful
  rotation is lost, the client retries with the presented token, which is
  now a reuse: the family is revoked and the user re-authenticates. This is
  inherent to rotation; there is no grace period. A Redis rotation resent
  by the client library after a lost reply is recognized, though, and does
  not count as a reuse.

These guarantees rest on deployment assumptions, detailed in the package
documentation of [`store/sql`](../oauth2/store/sql/doc.go) and
[`store/redis`](../oauth2/store/redis/doc.go): every read reaches the
primary (no replica reads, no client-side caching), the store's PostgreSQL
transactions run at READ COMMITTED (it pins the level) and
MySQL tables use InnoDB, Redis is a standalone server or a Sentinel primary
(not Cluster) running 6.0 or later with `maxmemory-policy noeviction`, no
family row or key is deleted before it expires, and durability is the
backend's: a revocation acknowledged by a primary that fails before
persisting or replicating it can be lost in a failover. Only SQLite is
exercised in CI; the PostgreSQL and MySQL guarantees rest on their locking
semantics.

### Offline JWT access tokens

The store's revocation reaches every token looked up in the store —
`/introspect`, a resource server calling `LookupAccessToken` — but not a
resource server that verifies JWT access tokens offline, from their
signature and claims (`jwtsec.BearerVerifier`): such a token stays valid
until its `exp`, whatever happened to its family — including the tokens
revoked after an authorization-code replay: deleting or flagging store
records never invalidates a signature. The RFC 9068 payload the
`jwtsec` signer emits carries no family or token identifier (`jti`), so it
cannot be deny-listed today either. RFC 7009 §2.1 acknowledges such a
propagation delay and asks implementations to minimize it; its §3 leaves
immediate revocation of self-contained tokens to non-standardized backend
interaction, and suggests short-lived access tokens instead. To bound the
window:

- keep `grant.Config.AccessTTL` short when access tokens are JWTs;
- for high-value operations, validate the token against the authorization
  server — RFC 7662 introspection, or `LookupAccessToken` when the resource
  server shares the store — rather than offline;
- or issue opaque access tokens, which only the store can validate.

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

## OpenID Connect client

`oidc/client` logs users in through external OpenID Providers. The
provider is trusted for what it asserts about its own users only; the
callback request, the browser and — in a SaaS — the provider's metadata
are attacker-influenced.

- **Browser binding** — a login is bound to the user agent that started
  it: `Begin` draws a 256-bit binding secret the user agent keeps (an
  HttpOnly `__Host-` cookie with `StartLogin`), and the callback must
  present it. The nonce and the PKCE verifier are HMAC-SHA256 values of
  that secret (OpenID Connect Core §15.5.2), so the transaction store holds
  only a hash of the state and of the binding: reading the store yields
  nothing that completes a login, and a stolen state alone cannot be
  replayed from another browser (login CSRF, RFC 9700 §4.7).
- **Store integrity** — every transaction carries an integrity MAC over all
  its fields, keyed by a value derived from the binding secret, which
  `Complete` verifies before using any stored field: a transaction altered
  in the store — a stripped `max_age` or `acr_values`, a rewritten
  `AppState` or redirect URI — fails its login
  (`ErrTransactionIntegrity`). The user agent of a login holds its binding
  secret, though: an attacker who can write to the store can still relax
  the `max_age` and `acr_values` checks of logins it runs with its own
  browser. When step-up authentication matters, protect the store's
  integrity (authentication, network isolation), not only its availability.
- **Single use** — `TransactionStore.Consume` removes the transaction
  atomically, unknown first, then expired whatever the binding, then a
  binding mismatch, which keeps the transaction so that a leaked state
  cannot burn the victim's login. A replayed callback finds nothing and
  never reaches the token endpoint.
- **Mix-up attacks** (RFC 9700 §4.4) — give every connection its own
  redirect URI, distinct from every other connection's (by scheme, host,
  port, path or query parameter): `Complete` refuses a response received on
  another URL than the connection's redirect URI, and a transaction of
  another connection, issuer, client, redirect URI or response mode. A
  provider advertising RFC 9207 must also send the `iss` parameter,
  compared with its issuer. Never route callbacks by the state value.
  Distinct redirect URIs leave the gap RFC 9700 §4.4.2.2 names — an
  attacker registering, at the honest provider, a client with the redirect
  URI of its own connection; RFC 9207 closes it, so prefer providers that
  support it. Behind a reverse proxy, `HandleCallback` compares the Host
  header the proxy forwards: preserve it, or give `Complete` the public
  URL.
- **ID Token** — validated per OpenID Connect Core §3.1.3.7 before anything
  is returned: asymmetric algorithms only (HMAC and `none` refused), `typ`
  absent or `JWT` (an RFC 9068 `at+jwt` access token is refused), keys from
  the configured issuer's `jwks_uri` only (`jku`, `x5u`, `jwk`, `x5c`
  ignored) through a bounded cache that refetches once, rate limited, for
  an unknown key, and never on a bad signature from a known one; `iss`,
  `aud` (further audiences only when trusted), `azp`, `exp`/`iat`/`nbf`
  within a bounded skew, `nonce`, `auth_time` against `max_age`, `acr`
  against the requested `acr_values`, and `at_hash` when present. Every
  JSON document is decoded strictly: duplicate member names, names that
  differ only by case, invalid UTF-8 and unpaired surrogates are refused,
  so an application decoding claims itself never reads another member than
  the one validated.
- **Identity** — the verified identity is the issuer and subject pair
  (Core §5.7). Link accounts on (connection or tenant, issuer, subject);
  never on email, phone or username, which another subject or provider can
  assert. For Microsoft Entra ID, configure the tenant's own issuer: the
  templated multi-tenant issuers are refused.
- **Cookies** — binding cookies are `__Host-` (Secure, Path=/, no Domain:
  a sibling subdomain cannot plant one), HttpOnly, named after the state so
  parallel logins coexist, capped at four per browser, and deleted by the
  callback. SameSite is Lax for the `query` response mode — the callback
  is a top-level GET — and None for `form_post`, whose cross-site POST
  carries no Lax cookie; an opt-in headless-Chrome test checks both.
  `InsecureCookies` drops Secure for local http development only, and is
  refused with `form_post`.
- **CSRF** — exempt the callback route from CSRF middleware in `form_post`
  mode: the cross-site POST is the protocol, the binding cookie its
  defense. Start logins on a user action from the application's own
  origin (a POST behind `http.CrossOriginProtection` or a CSRF token) and
  rate limit them: each start writes a transaction.
- **Redirect targets** — `AppState` comes back from the store verbatim;
  validate it before using it as a redirect target. After a successful
  callback, create a fresh session and answer 303 to a clean URL, so the
  code leaves the browser history (RFC 9700 §4.3.1).
- **Account linking** — linking an external identity to an account that
  is already signed in is a login started on the victim's behalf if it can
  be forged: on a hostile tenant's connection, a forged link start would
  silently attach the attacker's identity to the victim's account. Start a
  link only with a CSRF-protected POST after a recent re-authentication,
  put a random value bound to the local session in `AppState`, and after
  `Complete` link only when it matches the current session's value — never
  link on an identity whose `AppState` does not prove the link was started
  by that session.
- **Provider errors** — `AuthorizationError` and `TokenError` carry the
  provider's `error`, `error_description` and `error_uri`: untrusted text,
  their `Error()` prints the code only. Never render the description or the
  URI. The errors of `New` (discovery) may name the resolved address of an
  allowed destination: when tenants configure issuers, log them and show a
  generic message.
- **Tokens** — token and UserInfo requests never follow redirects;
  `UserInfo` sends an identity's access token only to the UserInfo
  endpoint of the connection that issued it, and returns claims only when
  their `sub` is the identity's. `String`, `GoString` and `LogValue` redact
  secrets, but `json.Marshal` of an `Identity` serializes its tokens.
- **Caveats** — sending `acr_values` makes `acr` required, among the
  requested values; a public client (`none`) requires the provider to
  advertise S256. `github.com/coreos/go-oidc` was evaluated and rejected:
  its verifier skips nonce, azp, iat, `typ`, auth_time and acr, and its key
  set refetches on every failure without rate limit (see the package
  documentation of `oidc/client`).

## Outbound requests (SSRF)

Modules that fetch URLs from configuration or remote metadata (OpenID
Connect discovery, JWK Sets, token and UserInfo endpoints, SAML metadata)
use `outbound.NewClient`. In a multi-tenant deployment those URLs are
attacker-influenced — a tenant administrator types an issuer, a discovery
document names its own endpoints — so the client defends the server's own
network:

- **Destinations** are judged on the address actually connected to, in
  `net.Dialer.ControlContext`, after DNS resolution: a name that resolves
  to a public address when vetted and to an internal one when dialed (DNS
  rebinding) is still refused. Refused by default: loopback, private
  (RFC 1918, RFC 4193 unique-local), shared (RFC 6598, CGNAT), link-local
  (including `169.254.169.254` and the other cloud metadata endpoints),
  multicast, unspecified, reserved, documentation and benchmarking space,
  and any scoped (zoned) address. IPv4-mapped IPv6 addresses and NAT64
  (`64:ff9b::/96`) addresses are judged on the IPv4 address they reach;
  IPv6 is limited to `2000::/3` minus its special-purpose blocks (Teredo,
  6to4, documentation), so an unknown or future reservation is refused.
- **URLs** must be https (http only with `AllowHTTP`, for development), carry
  no userinfo, and name an ASCII host: non-ASCII names (which `net/http`
  would map to another name before dialing), percent-encoded or
  underscore characters, empty labels and trailing dots are refused, so a
  host check in `CheckURL` sees the name actually dialed.
- **Redirects** are not followed unless `MaxRedirects` allows it; every
  hop is re-checked, and https→http is always refused. Credential-bearing
  requests (token, UserInfo) never follow redirects.
- **Resources** are bounded: one timeout for the whole exchange (10 s by
  default), a size cap on every body (1 MiB by default) counted after
  transparent decompression — a gzip bomb fails — and a 64 KiB header cap.
- **No ambient authority**: no proxy (an environment proxy would be
  judged instead of the destination), no cookie jar, TLS 1.2 or later with
  verified certificates.

Exemptions are explicit: `AllowedPrefixes` for an on-premises identity
provider's subnet (or `outbound.LoopbackPrefixes()` in tests). Any port
is allowed by default; restrict ports and hosts in `CheckURL`, and deny
specific public addresses in `CheckAddr`. Only the well-known NAT64 prefix
is decoded: on a network translating a network-specific prefix (RFC 6052),
refuse that prefix in `CheckAddr`, or its addresses reach the private IPv4
addresses they embed.

Host names ending in a number (`127.1`, `2130706433`, `0x7f.1`) are refused
before `CheckURL`: resolvers read them as IPv4 addresses, so a host check
would vet another name than the one dialed. A refused destination is never
named in an error, but the errors of allowed destinations may name their
resolved address and port, and every error tells whether a name is
refused: when tenants supply URLs ("test this connection"), log the error
and show them a generic message, or the error text becomes an oracle on
the internal network.

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
- [ ] Use `Profile20BCP` or stricter; do not enable the `implicit` /
      `password` legacy grants without a documented reason.
- [ ] Give every confidential client that authenticates with a secret a
      high-entropy one. Register a client that cannot keep a secret as
      public (`none` + PKCE), and list its `GrantTypeValues`: an empty
      list allows every grant, `client_credentials` included.
- [ ] Register the resource servers calling `/introspect` as confidential
      clients, and set `ServerConfig.IntrospectionPolicy` when several
      resource servers or tenants share the authorization server.
- [ ] Give `ServerConfig.Storage` and every grant the same store, and wire
      `ServerConfig.OnError` and `grant.Config.OnError` to the same sink:
      failed family revocations are reported there.
- [ ] With `store/sql`, periodically delete rows past `expires_at` —
      consumed authorization codes included, never a family row before
      it — in the deadlock-free order the package documentation gives;
      with `store/redis`, run Redis 6.0+ standalone or behind Sentinel with
      `maxmemory-policy noeviction`, and read from the primary only. A
      revoked family whose state is lost before it expires can be revived.
- [ ] Keep JWT access tokens short-lived: a store revocation does not
      reach resource servers that verify them offline.
- [ ] Make the `IssuerResolver` return the same issuer for `/authorize` and
      `/token` of a realm, and authenticate users within
      `AuthorizeRequest.Issuer` in the `ConsentFunc`.
- [ ] With `store/sql`, apply the `ALTER TABLE` statements of each release
      (MIGRATION.md) before deploying it; keep PostgreSQL databases in
      `UTF8` and MySQL tables in `utf8mb4` with a strict `sql_mode` — a
      non-strict MySQL truncates an over-long value instead of refusing it.
- [ ] Serve over HTTPS so `Secure` cookies and bearer tokens are protected.
- [ ] Supply at least two session keys so rotation is possible without
      invalidating live sessions.
- [ ] Install an OpenTelemetry `TracerProvider` to collect the spans.
- [ ] Keep the zero `outbound.Policy` in production; exempt only the exact
      subnets of on-premises identity providers in `AllowedPrefixes`, and
      restrict hosts and ports in `CheckURL` when tenants configure URLs.
- [ ] Give every OpenID Connect connection its own redirect URI
      (`/oidc/{connection}/callback`), registered exactly at its provider.
- [ ] Use a shared `TransactionStore` (`oidc/client/store/sql` or
      `store/redis`) when several instances serve callbacks, and schedule
      `PurgeExpired` with the SQL store; restrict write access to it when
      you rely on `max_age` or `acr_values`.
- [ ] Link accounts on (connection, issuer, subject), never on email;
      create a fresh session after each login.
- [ ] Start logins with a same-origin POST and rate limit them; exempt only
      the `form_post` callback routes from CSRF middleware.
