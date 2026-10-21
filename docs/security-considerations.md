# Security considerations

This document records the security posture of the library: the defaults it
ships, the attacks it defends against, and the choices left to the operator.

## Password hashing

Two `password.Hasher` implementations are shipped:

- **Argon2id** — `NewArgon2idHasher(params)`. The default profile
  (`DefaultArgon2idParams`) is the minimum of the OWASP Password Storage
  Cheat Sheet: memory 19 MiB, time 2, parallelism 1, 32-byte key, 16-byte
  salt. RFC 9106 §4 recommends stronger options (2 GiB, t=1, p=4; or 64 MiB,
  t=3, p=4 when memory is scarce): raise the parameters towards them when the
  hardware allows.
- **bcrypt** — `NewBCryptHasher(cost)`, default cost 10 (`bcrypt.DefaultCost`,
  the OWASP minimum; lower costs are for tests). bcrypt processes at most 72
  bytes: a longer password is refused by `Hash` and `Verify`
  (`ErrPasswordTooLong`) rather than verified on its first 72 bytes — NIST
  SP 800-63B-4 §3.1.1.2 requires the entire password to be verified. That
  caps passwords of multi-byte characters below the 64 characters
  SP 800-63B-4 asks verifiers to permit: prefer Argon2id.

**Stored hashes are untrusted input.** `Verify` decodes the parameters of the
stored hash and checks them before any hashing: argon2id version 19, each of
`m`, `t`, `p` exactly once, `t ≥ 1`, `p ≥ 1`, `m ≥ 8p` (RFC 9106 §3.1), salt
and tag of 16 to 64 bytes (library policy: RFC 9106 sets no salt minimum,
§4 calls 128-bit salts and tags sufficient) → `ErrMalformedHash`; a cost
above the hasher's limits → `ErrCostLimitExceeded` (argon2id: 256 MiB, 10
passes and 16 lanes by default, `WithArgon2idLimits`; bcrypt: cost 14,
`WithBCryptMaxCost`; both inclusive and raised to the hasher's own
parameters). A hash imported from an untrusted source or written by an
attacker can neither crash the process, exhaust its memory or CPU, nor
accept random passwords. Empty passwords are never hashed nor accepted
(RFC 8265 §4.1).

`NeedsRehash` lets a login flow transparently upgrade a stored hash when the
operator raises the cost factor. Call it after a successful `Verify` and
re-hash if it returns true.

A plain mismatch returns `(false, nil)` — only malformed or out-of-bounds
input, a password too long for the algorithm or context cancellation
produces an error. Never store or log the cleartext password.

**Unicode.** The hashers hash the password's bytes as given, so they verify
the hashes of systems that never normalized. NIST SP 800-63B-4 §3.1.1.2 says
verifiers SHOULD apply NFC to Unicode passwords (RFC 8265 §4.2 too): wrap
the hasher in the decorator of the `password` package documentation, at
enrollment and at login.

## Account enumeration

`basic.Authenticator` answers every refused attempt — unknown user, loader
error, account without a password, disabled/locked/expired account, password
mismatch — with `security.ErrInvalidCredentials` at the client boundary, and
spends the same work on each: exactly one password verification, against
the user's hash or against a dummy hash the configured hasher made at
construction; the account state is read only after the verification. The
detailed cause stays in the wrapped error chain for server-side telemetry
only. Do not mirror it in the HTTP/gRPC response.

What remains measurable, and how to close it:

- **Stored hashes at other parameters** cost another time than the dummy:
  configure the hasher with the parameters of your stored hashes and
  implement `basic.PasswordRehasher` on your loader, which re-hashes a
  stored hash that `NeedsRehash` after a successful login.
- **The loader's own latency** (a cache hit for known users, a slower miss)
  is the application's: make unknown and known lookups cost the same.
- A stored hash `Verify` refuses (malformed, above the limits) fails without
  hashing — an operator data problem, not reachable by a client.
- Under overload an attempt that gets no verification slot answers 503
  (`ErrUnavailable`) whatever the account, so overload reveals nothing.

Malformed credentials — control characters, format characters (Unicode Cf:
zero-width joiner and space, soft hyphen, bidirectional overrides, byte
order mark), line and paragraph separators, invalid UTF-8, more than 3072
bytes, an empty user-id — are refused before the loader runs, without a
verification and with one error: a property of the input, not of an
account. The extractor and the `Authenticator` apply the same rules, so a
form login that builds the value with `basic.New` is checked too, and such
a character never reaches the application's lookups and logs (log
injection, a user-id that displays as another one). RFC 8264's
FreeformClass, the base of RFC 8265's OpaqueString profile for passwords,
disallows them too (but for the zero-width joiner and non-joiner after a
virama, which this library refuses as well): refuse them when a password or
a user-id is chosen, or the account cannot sign in with Basic (reset the
password; rename the account or give it an alias — a Persian or Indic name
written with U+200C or U+200D, for instance).

### Online guessing and hashing cost

Basic authentication runs a full password verification on every request,
and since any username now costs one, a flood of attempts costs the server
CPU and memory (19 MiB per default Argon2id verification). The
`Authenticator` therefore runs at most `runtime.GOMAXPROCS(0)` verifications
at once by default (`WithMaxConcurrentVerifications`); further attempts wait
for a slot until their request context ends, then answer 503. Hashing is
CPU-bound: more parallel verifications than cores add latency and memory,
not throughput. Bound the request time (`http.TimeoutHandler`): `net/http`
request contexts carry no deadline.

Limit failed attempts per account and per client (NIST SP 800-63B-4
§3.1.1.2, §3.2.2 — verifiers SHALL rate-limit failed attempts): the library
ships `security.AttemptLimiter` and its in-memory implementation
`throttle.MemoryLimiter` (see [Attempt limiting](#attempt-limiting)): give
the `Authenticator` one with `basic.WithAttemptLimiter`. It keys the
attempts on the user-id lower-cased — `basic.WithAttemptSubject` when your
store merges other variants (accents, Unicode forms) — and on the client
address. Prefer exchanging Basic credentials once for a session or a token
over sending them on every request. Form logins and the OAuth2 `password`
grant's `ResourceOwnerVerifier` can reuse `basic.Authenticator` to get the
same protections.

## JWT

`jwtsec` defends against the classic JWT attacks:

- **`alg=none`** — rejected. The verifier parses with an explicit algorithm
  allowlist, so an unsigned token never reaches key resolution; an
  algorithm outside the list is refused with `ErrAlgorithmNotAllowed`.
- **Algorithm confusion** (HS256 forged with an RSA public key) — the
  default allowlist is asymmetric only: `RS256/384/512`, `PS256/384/512`,
  `ES256/384/512`, `EdDSA`. HMAC algorithms are **not** allowed by default;
  enable them with `WithAllowedAlgorithms` only when both ends share a
  symmetric secret and you understand the trade-off. Every verification key
  is bound to one algorithm (RFC 8725 §3.1): its `Algorithm` must equal the
  token's `alg` — a key without one verifies nothing — and an asymmetric key
  must pass `PublicKey.Validate` (RSA of at least 2048 bits, the algorithm's
  curve, a public key: a private key or a `jose.JSONWebKey` wrapper verifies
  nothing; an Ed25519 key must have a canonical y-coordinate, RFC 8032
  §5.1.3, that is not one of a point of small order — forgeries verify
  against the all-zero key and the identity point; a y-coordinate of no
  point of the curve is not detected, and verifies nothing). A `kid` shared
  by several keys designates none.
  RSASSA-PSS signatures must use a salt of the hash size (RFC 7518 §3.5;
  go-jose alone accepts any).
- **Claim smuggling** (RFC 7519 §4, §7.3, §10.1.1) — claims are decoded
  case-sensitively, by go-jose's decoder, into `StandardClaims` and into the
  caller's `claimsOut` alike. A claims set whose member names repeat —
  exactly, through an escape, or under Unicode case folding (`"Sub"`,
  `"EXP"`, `"ſub"`) — at any depth is refused, so no case-folding consumer
  (Go's `encoding/json`, .NET's `OrdinalIgnoreCase`, approximately) can read
  another value than the verifier did. So are invalid UTF-8, unpaired
  surrogate escapes, a payload that is not one JSON object, and a registered
  claim of the wrong JSON type — `"nbf": null` does not disable the
  not-before check.
- **Oversized and malformed tokens** — a token over
  `DefaultMaxTokenSize` (16 KiB, `WithMaxTokenSize`) is refused before any
  decoding, and so is a JOSE header that decodes to more than 4 KiB,
  whatever the token bound: go-jose decodes the header into maps, 70 to 260
  times its size depending on its shape, before checking the algorithm
  (about 1 MiB and 1 ms at the bound, `BenchmarkVerifyHostileHeader`), and
  the payload is only base64-decoded before the signature is verified;
  only the canonical compact serialization is
  accepted (unpadded base64url, no whitespace, zero pad bits), with a strict
  JSON header that uses neither `crit` nor `b64` (RFC 7515 §4.1.11, RFC 7797
  §7: a JWT never uses `b64: false`). Values copied from a token into errors
  and span attributes are clipped to 128 bytes. Cap the transports as well:
  `http.Server.MaxHeaderBytes` (1 MiB by default) and
  `grpc.MaxHeaderListSize` (16 MiB by default) of about 64 KiB.
- **Keys named or carried by the token** — a header holding `jwk`, `x5c`,
  `jku` or `x5u` (RFC 7515 §4.1.2, §4.1.3, §4.1.5, §4.1.6), whatever its
  value, is refused with `ErrMalformedToken` before go-jose parses the header.
  go-jose parses `jwk` and `x5c` before it checks the algorithm, the key or
  the signature; up to v4.1.5 it validated an embedded RSA private key there,
  at a cost cubic in its size, so one unauthenticated 16 KiB token cost
  minutes of CPU (GHSA-mgcc-cww5-fp2q). RFC 7515 §4 would let a recipient
  ignore these members: refusing them is a local policy — keys come from the
  configured key set only (RFC 7515 §6; RFC 9068 §4 for resource servers), and
  a URL in a token is never followed (RFC 8725 §3.10). Issuers that send them
  cannot be served: Cloud Foundry UAA and SAP BTP XSUAA put `jku` in every
  token header. `x5t` and `x5t#S256` are accepted and ignored.
- **Time claims** — `exp` is required unless `WithOptionalExpiry`; the
  token is expired from `now == exp + skew` on (RFC 7519 §4.1.4: the current
  time MUST be before `exp`); `nbf` is inclusive; an `iat` in the future is
  refused. NumericDates outside 1970–9999 are refused, so a year-1 `exp` (a
  zero `time.Time`) cannot make a token immortal, and no signer can emit
  one. The skew is at most `MaxClockSkew` (5 minutes).

The verifier also validates `iss` and `aud` when configured, and resolves
keys by `kid` against a JWKS provider (static or remote).

- **Token confusion** (RFC 8725 §3.11–§3.12) — the OAuth2 access tokens
  `NewOAuth2AccessTokenSigner` signs are typed `at+jwt` and carry a `jti`
  (RFC 9068 §2.1, §2.2); OpenID Connect ID Tokens are typed `JWT`.
  `BearerVerifier`, the resource-server adapter, refuses at construction a
  verifier without `WithIssuer`, `WithAudience` and
  `WithType(TypeAccessToken)`, or with `WithOptionalExpiry` — RFC 9068 §4
  requires the resource server to check `typ`, `iss`, `aud` and `exp` — so an
  ID Token, or an access token minted for another API, is refused. An
  authorization server that types its access tokens `JWT` needs
  `WithAccessTokenType("JWT")` (and the verifier's `WithType("JWT")`): such
  tokens are told apart from ID Tokens by their audience only, which is safe
  only when the resource server's audience is never the `client_id` of a
  client of that issuer. Untyped access tokens are never accepted by
  `BearerVerifier`. `NewVerifier` keeps these checks opt-in for other JWTs.
- **Client tokens versus resource-owner tokens** (RFC 9700 §4.15) — a
  `client_credentials` token's `sub` is its client ID (RFC 9068 §2.2), so a
  client registered under a user's subject would get a token naming that
  user. `StandardClaims.ClientID` carries `client_id`, and the principal of
  `BearerVerifier` is an `AccessTokenPrincipal` whose `SubjectIsClient()`
  reports `sub == client_id`: refuse resource-owner data when it is true.
  It is a refusal rule only — a user whose subject equals the ID of the
  client they use reports true as well — so grant client privileges by
  `ClientID()` and scopes. Amazon Cognito's client-credentials tokens are
  classified alike; Keycloak (service-account UUID), Auth0 (`…@clients`),
  Okta and Microsoft Entra ID give client tokens subjects of their own and
  always report false. A token without `client_id` reports false too: with
  an issuer that sets `sub` to the client ID but omits `client_id`, the
  resource server cannot tell the two kinds apart and relies on disjoint
  client and user identifiers only. Check the principal's type with a
  checked assertion: another authenticator, or the anonymous fallback,
  gives another principal.
- **Remote key sets** — `NewRemoteJWKS` fetches through
  [`outbound`](#outbound-requests-ssrf): https only, publicly routable
  destinations judged at dial time, no redirect, no proxy, 10 s and 1 MiB.
  An internal JWKS host needs `WithOutboundPolicy` (exempt its subnet in
  `AllowedPrefixes`); `WithHTTPClient` is an explicit opt-out that keeps the
  10 s / 1 MiB bounds and still refuses a response that arrived over http
  for an https URL. Whatever the client, the redirects it may follow
  (`MaxRedirects`, or the opt-out client's own policy) stay on the origin
  (scheme, host and port) of the JWK Set URL: a hop to another origin fails
  with `outbound.ErrRedirectNotAllowed`, so another server's keys never
  verify tokens. The set is refreshed in the background after the TTL
  (5 minutes by default) and on a token with an unknown `kid` — at most once
  per `MinKeySetRefreshInterval` (10 s), one fetch shared by every caller,
  never under a lock, not aborted when a caller gives up; failed fetches
  back off up to 5 minutes while the cached set keeps serving, until it is
  older than `MaxKeySetStaleness` (24 h). Each key is validated on its own
  and an unusable one ignored (private or symmetric material, `use` other
  than `sig`, `key_ops` without `verify`, unknown `kty` or curve, RSA outside
  2048–4096 bits, an `alg` the key cannot verify); a valid set without
  usable keys replaces the previous one. An outage is
  `ErrKeySetUnavailable`, which wraps `security.ErrUnavailable` (503 /
  Unavailable), never an invalid token. The provider prints and reports its
  URL without userinfo or query.
- **Signing keys** — `NewSigner` and `NewOAuth2AccessTokenSigner` return an
  error for a key unfit for its algorithm (RSA under 2048 or over 4096 bits,
  another curve, a public key, an HMAC secret shorter than its hash); KMS and
  HSM keys (`jose.OpaqueSigner`) are checked through their public half.
  Every token carries its key's `KeyID` as `kid` (RFC 7515 §4.1.4) — HMAC
  tokens included, so HMAC keys rotate like the others. An opaque PS* signer
  is checked at every signature: one whose salt is not the hash size —
  go-jose's `cryptosigner.Opaque` over an in-process key — makes `Sign` fail
  with `ErrInvalidKey`, so no token is issued that verifiers refuse.
  `MarshalJWKS` refuses an RSA key over 4096 bits too. The 4096-bit cap is
  go-jose's since v4.1.6: a larger published key breaks its consumers — this
  library's remote key sets and `oidc/client` ignore it, go-jose's
  `JSONWebKeySet` (go-oidc relying parties among others) refuses the whole JWK
  Set — so tokens signed with one would verify nowhere. The bound is the
  library's own: raising the process-wide `jose.MaxRSAModulusBits` does not
  move it. The RFC 9068 signer refuses claims missing a REQUIRED value — an
  empty `iss`, `sub`, `aud` or `client_id`, a zero `iat` or `exp` — so an
  `IssuerResolver` must return a non-empty audience for JWT access tokens.
- **Token strings are not unique** — an ECDSA signature has a second valid
  form (RFC 7518 §3.4 has no low-S rule; refusing it would refuse half of
  the legitimate tokens, and normalising this package's own signatures
  would not remove the twin anyone can compute): never key a cache, replay
  check or deny-list on the token string — use `jti`, or accept only the
  string the store holds (`WithActiveTokenCheck`).

## OAuth2

- **PKCE** — `authorization_code` requires PKCE under `Profile20BCP` and
  `Profile21Draft`, and of every client that is not confidential — public
  or untyped — under every profile (RFC 9700 §2.1.1); under `Profile20` it
  is optional for a confidential client unless `grant.Config.RequirePKCE`
  is set. `S256` is the only method accepted
  under BCP / 2.1; `plain` is tolerated only under `Profile20`. Both ends
  enforce the RFC 7636 syntax: `/authorize` answers `invalid_request` to a
  `code_challenge` that is not 43–128 unreserved characters (`plain`) or
  not the unpadded base64url SHA-256 digest (`S256`), and, for a code
  bound to a `code_challenge`, `/token` answers `invalid_grant` to a
  `code_verifier` that is not 43–128 unreserved characters. The code is
  consumed whether the verifier is malformed or wrong. Well-formed
  verifiers are compared in constant time. A `code_verifier` sent for a
  code issued without `code_challenge` is refused with `invalid_grant`
  under every profile (RFC 9700 §4.8.2, the PKCE downgrade attack: an
  attacker strips `code_challenge` from its own authorization request and
  injects the code into a victim's session); a parameter without value
  counts as absent (RFC 6749 §3.1). The refusal burns the code but revokes
  nothing: a replay of a code redeemed without PKCE still revokes its
  tokens, whatever `code_verifier` it carries.
- **Client policy** — fail closed: a client may use only the grant types it
  declares (`Client.GrantTypes`, compared exactly; empty allows none) and
  request only the scopes it declares (`Client.Scopes`; empty allows none).
  `/token` checks the grant type for every grant, custom ones included,
  before the grant runs, so a refused request consumes nothing, and
  `/authorize` checks the grant of the response type (`authorization_code`
  for `code`, `implicit` for `token`) before the extension and the
  `ConsentFunc` run;
  `client_credentials` refuses every client that is not confidential (RFC
  6749 §4.4), and its tokens' `Subject` is the client ID (RFC 9068 §2.2) —
  a resource server reading the store tells them from a resource owner's by
  `AccessToken.ClientID == AccessToken.Subject` (or an empty
  `ExtensionData`), and keeps client IDs out of the user-subject namespace
  when clients choose them (RFC 9700 §4.15.1); a consent narrows the requested scope, never broadens it; a
  refresh token goes only to a client declaring `refresh_token` (RFC 9700
  §4.14.2), and a refresh issues an access token only within the client's
  current scope registration, so shrinking a registration takes effect at
  the next refresh. Refusals caused by an empty declaration reach `OnError` with
  `ErrNoGrantTypesDeclared` / `ErrNoScopesDeclared` as cause. Unlike RFC
  7591 §2, an empty grant-type list implies nothing, and scopes outside the
  registration are refused rather than ignored (OpenID Connect Core
  §3.1.2.1 says unknown scope values SHOULD be ignored).
- **Request parameters** — the parameters each endpoint reads are
  single-valued (RFC 6749 §3.1, §3.2): an empty occurrence is omitted, and
  one included more than once with a value is refused — at `/authorize` a
  repeated `client_id`, `redirect_uri` or `response_mode` with a bare `400`,
  any other with `invalid_request`; at `/token`, `/revoke` and
  `/introspect` with `invalid_request`, before the grant or the lookup
  runs. Callbacks get the request as received: a `ConsentFunc` or an
  `Extension` reads the core's parameters from the `AuthorizeRequest`, never
  with `r.FormValue`, which an empty occurrence can mislead.
- **Scope values** — every scope a client or a callback sends (the `scope`
  of `/authorize` and `/token`, `Consent.Scope`, `ExtensionGrant.Scope`) is
  parsed strictly as RFC 6749 §3.3 tokens — printable ASCII but `"` and `\`
  (NQCHAR), separated by SP; runs of SP and leading or trailing SPs are
  tolerated, any other whitespace is not — at most 100 tokens (repetitions
  included) and 4096 bytes. Anything else is `invalid_scope` (`server_error`
  for an extension), refused before the value is compared with anything.
  Comparisons are set lookups, so the work a request causes stays linear in
  its bounded size, and the server issues and stores scopes canonical:
  single-SP joined, duplicates dropped. A registered scope outside that
  syntax can never be requested; a scope the server stored itself is never
  refused for its syntax.
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
  the family. `RefreshTTL` is an inactivity expiry that every rotation
  restarts; `grant.Config.RefreshFamilyTTL` adds an absolute bound from the
  family's first issuance (`RefreshToken.FamilyIssuedAt`), which also ends a
  family a thief keeps alive by rotating a stolen token — zero, the
  default, sets none. Under `Profile20` rotation is opt-in (`RotateRefreshTokens`)
  for confidential clients only: without it their refresh token stays
  reusable until it expires, while the refresh token of a client that is
  not confidential — public or untyped — always rotates (RFC 9700 §2.2.2,
  §4.14.2); a `refresh_token` grant without a `RefreshTokens` generator then
  fails their refresh with `server_error`, which `NewServer` cannot detect.
- **Token storage** — access tokens, refresh tokens, and authorization
  codes are stored **hashed only** (HMAC-SHA256 with an empty key, via
  `oauth2.HashToken`). The store never sees cleartext, so a database
  compromise does not yield usable tokens. Tokens carry ≥ 128 bits of
  entropy, so the unkeyed hash is preimage- and brute-force-resistant.
- **Codes are consumed before they are validated** — a party holding a
  leaked code can burn it (presenting it with a wrong verifier, or as
  another client): it obtains nothing — client, issuer, redirect URI and
  PKCE still bind the code — but the legitimate exchange then fails with
  `invalid_grant` and the user authorizes again. This is deliberate:
  single use rests on one atomic consumption, validating first would need
  a non-consuming lookup in every store, and refusing a code that has
  leaked is the conservative outcome (RFC 6749 §4.1.2 requires refusing a
  reused code). Keep codes out of logs and `Referer` headers, and
  short-lived (`AuthorizeConfig.CodeTTL`).
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
  Security BCP and `Profile21Draft` the OAuth 2.1 draft: both refuse the
  legacy `implicit` and `password` grants, which only `Profile20` allows —
  opt-in, never by default.
- **Client authentication** — one method per request (RFC 6749 §2.3): an
  `Authorization` header with a body `client_secret`, several
  `Authorization` fields, or a repeated `client_id` / `client_secret` are
  `invalid_request` before any client is loaded, and a body `client_id`
  naming another client than the one authenticated is refused.
  `client_secret_basic` / `client_secret_post`
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
  `401 invalid_client`. Every failed client authentication reads the same —
  `401 invalid_client`, "client authentication failed", the Basic
  challenge — whether the client is unknown, of another issuer, presented a
  wrong secret, used a method it may not use or a malformed credential: the
  answer neither confirms a client exists nor discloses its type and
  methods; the detail reaches `OnError` only. Two residual signals remain,
  both acceptable since client identifiers are not secret (RFC 6749 §2.2):
  the response time — an unknown client skips `SecretMatches`, so a slow
  matcher (a password hash for human-chosen secrets) makes it ~100 ms
  faster: such a matcher runs a dummy verification for unknown clients — and
  `/authorize`, which tells an unknown `client_id` from an unregistered
  `redirect_uri` by design (RFC 6749 §4.1.2.1 asks it to inform the resource
  owner).
- **Client secrets and guessing** — a client secret is a password the
  server verifies on every `/token`, `/revoke` and `/introspect` request:
  RFC 6749 §2.3.1 has the authorization server protect these endpoints
  against brute force, and RFC 7662 §4 warns that an un-throttled
  `/introspect` lets an attacker fish for valid tokens. The server does not
  throttle — every failed client authentication answers the same `401
  invalid_client` and reaches `OnError` — so rate-limit the three endpoints
  per `client_id` and per source address in front of the handlers, and
  alert on the failures. Generate secrets with at least 128 bits of entropy
  (RFC 6749 §10.10: a guessing probability of at most 2^-128, 2^-160
  recommended — 32 random bytes), out of reach of online guessing. At
  rest, keep a hash: `DefaultClient` holds its secret in cleartext — for
  tests, examples and static configurations — and compares SHA-256 digests
  in constant time, so its timing discloses neither the secret nor its
  length; a production `Client` implements `SecretMatcher` over the stored
  SHA-256 of a generated secret, compared in constant time, or over a
  password hash for a human-chosen one (with the dummy verification above).
- **Token introspection** — RFC 7662 §4 requires the authorization server
  to authenticate the protected resources calling `/introspect`. A public
  client cannot authenticate: its `client_id` ships inside every copy of the
  app and RFC 6749 §2.2 forbids using it alone, and the authorization server
  MUST NOT rely on a public client's authentication — even with a secret —
  to identify it (RFC 6749 §2.3). Accepting one would let anyone read the
  validity and claims of a token they held — through `none`, or through
  Basic/Post with the client's registered secret — so `/introspect` refuses
  every caller that is not a confidential client. By default, any
  authenticated confidential client may then introspect any access token of
  the request's issuer, and a refresh token only if it was issued to it:
  refresh tokens are meant for the authorization server and their client
  (RFC 6749 §1.5), and a resource server that ignores `token_type` could
  accept one as a bearer token. RFC 7662 §4 adds that protected resources
  SHOULD be specifically authorized, and that when a token can be used only
  at certain resource servers the authorization server MUST determine
  whether it can be used at the caller: that decision is
  `ServerConfig.IntrospectionPolicy`, which sees the authenticated caller
  and the token's metadata before anything is disclosed — and replaces the
  default, so refuse refresh tokens to resource servers there too. A
  withheld token and a failed policy answer
  the same bytes as an unknown token (`{"active":false}`), so the response
  discloses nothing (its latency may still differ); a policy failure is
  reported to `OnError`.
- **Token revocation** — `/revoke` revokes the caller's own tokens of the
  request's issuer: a refresh token with its whole family, an access token
  with its family too (RFC 7009 §2.1). A token issued to another client, or
  under another issuer, is left untouched and answered with the `200` of an
  invalid token (RFC 7009 §2.2) — a deliberate deviation from RFC 7009
  §2.1, which refuses such a request with an error: the error would confirm
  to whoever holds a token that it is valid for another client.
- **Issuer binding (realms)** — a subject is only meaningful within its
  issuer (OIDC Core §16.15). Every endpoint resolves the issuer of the
  request through the `IssuerResolver` before it loads the client;
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
  authentication. `/introspect` and `/revoke` keep the same boundary: at
  the issuer the request resolves to, a token issued under another issuer
  answers `{"active":false}` and is not revoked (the answer is 200 all the
  same), so a client registered in several realms can neither read nor
  revoke another realm's tokens, and an `IntrospectionPolicy` only sees
  tokens of the request's issuer. A token recorded without issuer — written
  before tokens recorded one — is inactive at a non-empty issuer, but its
  client can still revoke it: revocation only takes away.
- **Clients and realms** — one `ClientStore` behind several issuers makes
  every client known at every issuer: a client of realm A could send realm
  B's end-users to B's genuine login page and obtain their codes and
  tokens once they consent. A client implementing `IssuerBoundClient`
  (`DefaultClient.IssuerValues`) exists at its issuers only: elsewhere
  `/authorize` answers the bare 400 of an unknown `client_id`, never
  redirected (RFC 6749 §4.1.2.1), and `/token`, `/revoke` and `/introspect`
  fail its authentication as any other (`401 invalid_client`, "client
  authentication failed"), whatever the secret — the same bytes in both cases, so
  realm B can neither be used by A's clients nor enumerate them or check
  their secrets. The binding is checked before the client's secret and
  redirect URI, and again on the client an authenticator returns. A
  multi-issuer deployment binds every client, or scopes its `ClientStore`
  by issuer.
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
- **Redirect URIs** — a request's `redirect_uri` must equal a registered
  one, byte for byte (RFC 6749 §3.1.2.3, RFC 9700 §2.1: simple string
  comparison, no pattern), with one exception RFC 8252 §7.3 makes
  mandatory: a registered loopback IP redirect URI (`http://127.0.0.1` or
  `http://[::1]`) accepts any port, the rest of the URI unchanged — native
  apps listen on an ephemeral port — and the code is bound to the URI
  requested. `http://localhost` gets no such variance (RFC 8252 §8.3
  recommends the IP literal). The registered URI a request resolves to must
  pass `oauth2.ValidateRedirectURI` — absolute, no fragment, a host, no
  userinfo and a port within 1–65535 for http(s), a private-use scheme
  holding a "." (RFC 8252 §8.4, which also rules out `javascript:`, `data:`
  and `urn:ietf:wg:oauth:2.0:oob`), a query naming no
  response parameter — or the request gets a bare 400, never a redirect
  (RFC 6749 §3.1.2.4); run the same function when registering clients.
  Responses keep the registered query byte for byte (RFC 6749 §3.1.2),
  and the implicit flow appends its fragment to a URI that has none.
- **Open redirection** — RFC 9700 §4.11.2: a registered client controlling
  its redirect URI could send users an erroneous request (an invalid scope)
  or a `prompt=none` one, and have the authorization server redirect them
  to its phishing page without anyone authenticating. Set
  `AuthorizeConfig.TrustedRedirect`: for a client it does not trust, every
  error detected before the resource owner authenticated — and a
  `Consent.Refusal` stating the request cannot complete without a user
  interface (`login_required`, `interaction_required`,
  `account_selection_required`, `consent_required`) — is a bare error page,
  never redirected. Without it, every registered client is trusted (RFC 6749
  §4.1.2.1 redirects errors once the redirect URI is validated). Once the
  resource owner authenticated, the code and an explicit `access_denied` are
  redirected to every client.
- **Authorization endpoint pages** — the `ConsentFunc` renders the login
  and consent pages, but every response of `/authorize` carries
  `X-Frame-Options: DENY`, `Content-Security-Policy: frame-ancestors 'none'`
  (added to a policy an outer handler set), `Cache-Control: no-store` and
  `Referrer-Policy: same-origin`: the authorization server MUST prevent
  clickjacking (RFC 6749 §10.13, RFC 9700 §4.16), its pages and redirects
  carry codes and states, and no `Referer` leaks the request URL to another
  origin (RFC 9700 §4.2.4). `same-origin`, not `no-referrer`: under
  `no-referrer` browsers send `Origin: null` on the consent page's own
  POST, which Origin-based CSRF checks then refuse. A `ConsentFunc` that
  must let a trusted origin frame its page replaces them on
  `w.Header()`. Browsers check framing on the final response only, so
  `prompt=none` in an iframe still follows the redirect. The authorization
  endpoint MUST be protected against CSRF (RFC 6749 §10.12): protect the
  request carrying the resource owner's decision — a token bound to their
  session, or `net/http.CrossOriginProtection` as `examples/oauth2` does —
  not the endpoint, to which clients may POST authorization requests. A
  redirect answering a POST is a `303` (RFC 9700 §4.12: only 303
  unambiguously turns the POST, and the credentials it may carry, into a
  GET), never a `307`.
- **Failures are outages, not refusals** — a `ClientStore` that fails is
  not an unknown client: answering `invalid_client` would tell a client its
  credentials are wrong (and push it to rotate them). `/authorize` answers a
  bare 500, `/token` and `/introspect` a `server_error`, `/revoke` a 503
  `temporarily_unavailable` (RFC 7009 §2.2.1), each reported to `OnError`;
  a store reports an unknown client with `(nil, nil)` or an error carrying
  `invalid_client`. A token lookup that fails at `/introspect` answers
  `{"active":false}` — a resource server fails closed (RFC 7662 §2.1) — and
  reaches `OnError`.
- **Request bounds** — RFC 6749 bounds no parameter, and `net/http` alone
  reads 10 MB of form. Every endpoint bounds the query and the body it
  parses to `ServerConfig.MaxRequestBytes` (64 KiB by default) —
  `invalid_request`, a bare 400 at `/authorize`, before any parameter is
  read; a declared `Content-Length` over the bound is refused before the
  body is. The values the server keeps or echoes are bounded too: the
  `state` echoed in every authorization response (at most 4096 bytes of
  VSCHAR, RFC 6749 Appendix A.5 — refused without echoing it), the `nonce`
  recorded with the code (512 bytes of UTF-8 without NUL, for every request
  — so no store is handed a multi-megabyte value to persist and re-encode),
  the scope (100 tokens, 4096 bytes) and the `client_id` (255 bytes: a longer
  one is unknown, never looked up). A 4 KiB `state` of unreserved
  characters keeps the redirect URL within the usual 8 KiB request-line
  limits; percent-encoding triples every other VSCHAR, so a state made of
  them reaches 12 KiB of `Location` — and an authorization server behind a
  proxy whose response-header buffer is smaller (nginx's
  `proxy_buffer_size` defaults to 4 KiB) needs that buffer raised. A body a
  middleware parses before the handlers (`r.ParseForm`, `r.FormValue`) is
  read without `MaxRequestBytes`: bound that middleware's reads too.
- **Mix-up defense (RFC 9207)** — every authorization response, code and
  implicit, success and redirected error, carries `iss`, the issuer the
  request resolved to, and the RFC 8414 metadata sets
  `authorization_response_iss_parameter_supported`: a client talking to
  several authorization servers — or to several realms of one
  `IssuerResolver` — compares it with the issuer it sent the request to and
  aborts on a mismatch (RFC 9700 §4.4.2.1), the defense RFC 9700 prefers to
  distinct redirect URIs. The issuer must therefore be a stable https URL
  without query or fragment (RFC 9207 §2): the server sends it as the
  resolver returns it. The one response without `iss` is the `server_error`
  answering an `IssuerResolver` failure — no issuer is known then. RFC 9207
  §2 asks for `iss` in error responses too, and §2.4 has RFC 9207 clients
  reject a response without it, so the independent code review of #84
  recommended a bare 500 instead; the redirect is kept so that RFC 6749
  clients learn of the failure (RFC 6749 §4.1.2.1 `server_error`), and RFC
  9207 clients discard it as they discard any response they cannot
  attribute — a documented deviation on a server-failure path that issues
  nothing.

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
- **Atomicity.** An issuance or rotation applies all its writes or none,
  never a part of them. One the store refuses — a revoked family, a reuse,
  a malformed pair — persists no token and consumes nothing: a failed
  exchange no longer leaves an access token behind. A backend failure can
  leave the outcome unknown: when the acknowledgement of a commit is lost,
  the call fails although all its writes may have been applied, and a
  client retrying the refresh then presents a consumed token — a reuse
  (see "Lost responses look like theft" below).
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
  never be lost within its retention — no eviction, no early cleanup. A
  consumed refresh token must not be lost either: one evicted from Redis,
  or deleted from SQL before its `expires_at`, reads as an unknown token
  when presented again — `invalid_grant`, revoking nothing — so a stolen
  token's reuse goes undetected.
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
persisting or replicating it can be lost in a failover. CI checks these
guarantees on SQLite and, in its "Store suites (real backends)" job
(`make test-backends`), on PostgreSQL 16, MySQL 8.0 and 8.4, MariaDB 11.4
(`internal/interop/sqlstores`) and Redis 7.4 (the conformance suite of
`oauth2/store/redis`). On other versions and engines they rest on the
locking semantics above.

### Offline JWT access tokens

The store's revocation reaches every token looked up in the store —
`/introspect`, a resource server calling `LookupAccessToken` — but not a
resource server that verifies JWT access tokens offline, from their
signature and claims (`jwtsec.BearerVerifier`): such a token stays valid
until its `exp`, whatever happened to its family — including the tokens
revoked after an authorization-code replay: deleting or flagging store
records never invalidates a signature. RFC 7009 §2.1 acknowledges such a
propagation delay and asks implementations to minimize it; its §3 leaves
immediate revocation of self-contained tokens to non-standardized backend
interaction, and suggests short-lived access tokens instead. To bound the
window:

- keep `grant.Config.AccessTTL` short when access tokens are JWTs;
- give `BearerVerifier` that backend interaction,
  `jwtsec.WithActiveTokenCheck`: it runs after every other check, in a
  `jwtsec.BearerVerifier.ActiveTokenCheck` span, and refuses the token
  (`ErrTokenInactive`, 401) unless the authorization server reports it
  active. With a store shared with the authorization server, look the token
  up by `oauth2.HashToken(nil, token)` with `LookupAccessToken` — an
  `invalid_grant` `*oauth2.Error` means inactive, any other error means the
  check could not be made (wrap `security.ErrUnavailable`: 503); otherwise
  call RFC 7662 introspection. Accept only a token found active, never
  deny-list token strings: an ECDSA token has a second valid form, which
  the store does not know and a deny-list would miss;
- or issue opaque access tokens, which only the store can validate.

## OpenID Provider

`oidc/provider` trusts the application's `Interaction` for who the end-user
is, never for the protocol rules:

- **Requests are checked before any interaction.** A repeated `client_id`,
  `redirect_uri` or `response_mode`, or a missing `redirect_uri`, answers a
  bare `400` that is never redirected; request objects and `registration`
  are refused; `nonce`, `claims`, `max_age` and hints are bounded; an
  `id_token_hint` must be an ID Token this issuer issued to this client,
  signed by a key it publishes.
- **Every approval is re-checked.** Before a code is issued, the provider
  checks the approval against the request — realm, `prompt=login` and
  `max_age` freshness, designated end-user, essential `acr` — and the
  authentication event itself (a subject of 1 to 255 printable ASCII
  characters, a time at most 5 s in the future, bounded `acr` and `amr`),
  and requires `openid` in the granted scope. A violation issues nothing.
  Freshness is compared at the second of `auth_time`; an application that
  must re-authenticate on `prompt=login` shows its login page itself.
- **`prompt=none` shows no UI**: `AuthorizeSilently` gets no
  `ResponseWriter`, and an OpenID request served outside
  `Provider.AuthorizeHandler` is refused before any `ConsentFunc` runs.
- **Realm-bound authentications.** An authentication counts in the realm
  (issuer) it was established in only. The realm is the issuer: where
  tenancy is finer — one issuer, several organizations — the `Interaction`
  must also check the session's tenant against `Request.Client`. Separate
  issuers isolate sessions, not clients: with one `ClientStore`, bind every
  client to its issuers (`oauth2.IssuerBoundClient`, see "Clients and
  realms" above) — a tenant-A client could otherwise send tenant B's
  end-users to B's genuine login page and obtain their identity and B's
  tokens once they consent. UserInfo refuses a token whose client is no
  longer registered at the issuer.
- **`prompt=none` reveals no session.** The provider's refusals — a
  session of another realm, of another end-user, a stale one, an unmet
  essential `acr` — carry the sentinels' fixed descriptions: on the wire
  they read as no session at all, so a client cannot probe the browser.
  The reason reaches the `ErrorHook` only; an `Interaction` refusing with
  its own description must not describe the session either.
- **`InteractionStartedAt`** must come from server-side state bound to the
  authorization request, never from the session or the request parameters:
  a forged value makes a stale session look fresh. The provider bounds it to
  `[ReceivedAt − 15 min, ReceivedAt + 5 s]` and ignores it under
  `prompt=none`.
- **Offline access needs consent** (OIDC Core §11): `offline_access` is
  dropped from every grant — OpenID or plain OAuth 2.0 — unless the
  `Decision` grants it (the end-user's consent, or the application's
  policy), and a refresh token issued to an OpenID grant without that
  consent fails closed. Wire `grant.Config.RefreshTokenScope =
  oidcprovider.ScopeOfflineAccess`: only the scope is gated, and a plain
  OAuth 2.0 grant gets refresh tokens per that setting.
- **Token confusion** (RFC 9068 §5, RFC 8725 §2.8, §3.11, §3.12): an ID
  Token's audience is the client ID, and every code exchange and refresh
  whose access-token audience is the requesting client's ID, or that of a
  client registered at the issuer that declares `authorization_code`, is
  refused (`server_error`) — the first tokens of `client_credentials` and
  `password` grants are checked only through the exchanges of the same
  issuer, so keep every
  `IssuerResolver` audience apart from relying parties' client IDs; JWT
  access tokens are typed `at+jwt`. Resource servers require that type —
  `jwtsec.BearerVerifier` refuses a verifier without
  `WithType(TypeAccessToken)` — so an ID Token is never accepted as an
  access token.
- **Keys.** Key rings are validated on every use (RS256 required, one key
  per algorithm and one algorithm per key, RSA of 2048 to 4096 bits,
  curves bound to algorithms) and fail closed; private and symmetric keys
  are never published. The keys of JWT access tokens belong in
  `KeyRing.Published`: one `jwks_uri` serves both (RFC 9068 §4).
- **Claims and accounts.** Only the claims the request and the end-user
  allow are released, and a `ClaimsSource` cannot override a protocol claim
  — not even under a case variant (`SUB`, `ſub`, `s.u.b`, `iß`, `ïss`) or a
  `#` alias (`sub#x`, `s#ub-fr`, `email#verified`) that a
  relying party matching names case-insensitively (Go's `encoding/json`
  among them) or normalizing them to camelCase would read as `sub` or
  `iss`. Other spellings of known claims
  (`Email`, `Roles`), names that are case variants of one another, invalid
  names and values whose member names would alias are dropped too; declare
  every application claim relying parties decide on in
  `Config.ClaimsSupported`, and keep the claim names end-users choose apart
  from them (see [oidc-provider.md](oidc-provider.md#claims)).
  `ErrUnknownSubject` stops an OpenID grant, or a plain OAuth 2.0 grant
  `Provider.AuthorizeHandler` approved, at its next exchange; other plain
  grants and issued access tokens are not checked, so disabling an end-user
  must also revoke their token families.
- **UserInfo serves personal data** to bearer tokens of OpenID grants of the
  request's issuer only, with `Cache-Control: no-store`. Allow browser
  origins (CORS) deliberately.
- **Issuers.** The issuer is an https URL without query or fragment
  (`http` only for an explicit loopback development opt-in). Discovery and
  the JWK Set are cacheable (`max-age=300`): an `IssuerResolver` must never
  derive the issuer from an unvalidated `Host` header.
- **The application's pages.** Login and consent pages need CSRF tokens and
  anti-framing headers (`X-Frame-Options: DENY`,
  `Content-Security-Policy: frame-ancestors 'none'`), must validate the URL
  they return to after a login (open redirect), and must never redirect with
  `307` — it would replay the posted credentials (OIDC Core §16.22).
  `examples/oidc-provider` does all of this.
- **Errors.** Refusals reach the `ErrorHook` with their cause; causes never
  carry a token, an `id_token_hint`, a `nonce`, a `login_hint` or a claim
  value.

## SAML Service Provider

`saml/sp` (package `samlsp`) consumes assertions from enterprise identity
providers (SP-initiated Web Browser SSO, Profiles §4.1). An assertion is a
bearer credential delivered through the browser, so the module trusts only
what the operator configured and refuses whatever it cannot read in exactly
one way. This section is the threat model; the
[integration guide](saml-sp.md) gives the exact trust tables, the identity
mapping, the deployment and rollover runbooks, and the test evidence.

### Trust

- **Explicit trust only.** Each connection pins the IdP entity ID and its
  signing certificates, imported from administrator-provided metadata
  (`ParseIdentityProviderMetadata`), fetched from the IdP's metadata URL
  (`FetchIdentityProviderMetadata`, `MetadataSource`) or configured
  directly. Importing is the act of trust: a signature embedded in the
  metadata is not verified, and an aggregate (`EntitiesDescriptor`) is only
  accepted with a pinned entity ID. Each imported certificate is trusted as
  a signing key by itself, without chain building: a signing
  `KeyDescriptor` carrying several certificates (a chain), or a key value
  that is not its certificate's key, is refused, and a
  CA or intermediate certificate must never be listed, not even in a
  descriptor of its own — its key would sign any user in (Metadata
  Interoperability Profile §2.5.1; the §2.6.1 deviations are listed in
  [saml-sp.md](saml-sp.md#34-metadata-trust)).
  Nothing in a response extends that trust: the `Issuer` must equal the
  connection's entity ID, and a `KeyInfo` certificate only *selects* one of
  the trusted certificates (it must equal it exactly). A `KeyInfo` without
  certificate (a `KeyName` or `KeyValue` only, which Core §5.4.5 allows)
  selects nothing: it is cut from the verified bytes where no digest covers
  it, after both parsers agreed on its position, and the signature is then
  verified as one without `KeyInfo`.
- **What is verified is what is used.** gosaml2 and goxmldsig verify the
  signature and decode the identity from the verified canonical bytes; no
  identity value is read from the raw document (only whether a
  `ProxyRestriction` carries a `Count`, whose value is the verified one),
  so a comment injected in a `NameID` (the CVE-2017-11427 class) cannot
  truncate it. The Response envelope (`Issuer`, `Destination`,
  `InResponseTo`, `IssueInstant`) and the `Status` are signed only when
  the Response is; unsigned, they only add refusals
  ([guide](saml-sp.md#31-signatures-and-what-is-read-from-where)). Before
  verification, a structural profile pins the single `Assertion` as a child
  of the `Response`, unique `ID`s and the placement of every signature, so
  signature-wrapping attacks have nothing to wrap (see
  `TestCompleteLogin_XMLSignatureWrapping`).
- **No parser differential on attributes.** The pre-check reads the raw
  tree with etree, goxmldsig and gosaml2 decode with `encoding/xml`, and
  the two disagree on attributes that share a local name: etree's
  `SelectAttr` returns the first in document order whatever its prefix,
  `encoding/xml` the last, after exclusive C14N has reordered them. An
  element carrying two attributes of one local name — whatever their
  prefixes, namespace declarations included — and a prefixed attribute
  named like a SAML or XML-DSig attribute (`foo:Algorithm`,
  `foo:Destination`) are therefore refused, and the pre-check reads
  unprefixed attributes only. Without this, `Algorithm="…sha256"
  foo:Algorithm="…sha1"` passed the allowlist while goxmldsig digested with
  SHA-1. The `xml` prefix is bound to the XML namespace, which defines
  `xml:lang`, `xml:space`, `xml:base` and `xml:id` only: any other `xml:`
  attribute is refused, since `encoding/xml` matches attributes by local
  name and read `xml:NotBefore` as the `NotBefore` the pre-check never saw.
- **Signed Response or signed Assertion** (Profiles §4.1.3.5/§4.1.4.5 as
  amended by errata E93 and E26): a signed Response covers its single
  assertion. The SP metadata omits `WantAssertionsSigned`.
- **Algorithms.** goxmldsig accepts SHA-1, inclusive C14N and more; `samlsp`
  enforces its own allowlist on every signature before any cryptography:
  RSA or ECDSA with SHA-256/384/512, SHA-256/384/512 digests, and exactly the
  enveloped-signature and exclusive C14N transforms, in that order; no
  `ds:Object` (errata E91). SHA-1 (`rsa-sha1`, `ecdsa-sha1`, SHA-1 digests)
  is accepted only from a connection that sets `InsecureAllowSHA1`;
  inclusive C14N, HMAC and unknown algorithms never are. IdP keys are RSA of
  2048 to 8192 bits or ECDSA P-256/384/521. ECDSA signature values are
  verified as ASN.1 DER, as goxmldsig implements them: an IdP emitting the
  XML Signature 1.1 raw `r‖s` encoding fails closed. The SP signs its
  AuthnRequests with RSA (`rsa-sha256`).
- **Encrypted assertions are refused** (`ErrEncryptedAssertionUnsupported`)
  and the SP publishes no encryption key: TLS protects the assertion in
  transit, and gosaml2's decryption code — the subject of several advisories
  — is never reached.

### Ambiguous responses are refused

Some responses the schema allows are refused because two readers could
take different identities from them: several assertions, several
`SubjectConfirmation` or `AuthnStatement` elements, an assertion without
`NameID`, a Response without `Issuer`, or a condition the SP does not
understand (Core §2.5.1.1). Each refusal has a typed error. Configure the
IdP to send one assertion carrying a persistent NameID:

- **AD FS** sends no NameID unless a claim issuance rule of the relying
  party trust issues one: add a rule (for example *Transform an Incoming
  Claim*) whose outgoing claim type is *Name ID* with the *Persistent
  Identifier* format, from an immutable source such as `objectGUID`.
- **Microsoft Entra ID** — the *Unique User Identifier (Name ID)* claim
  defaults to the user principal name, which can be reassigned: prefer
  `user.objectid` with the persistent format.
- **Okta** — set the Name ID format to *Persistent* and the application
  username to an immutable value.
- **Keycloak** — set the client's Name ID format to `persistent` and enable
  *Force name ID format*; signing the documents, the assertions or both
  works (the pinned interoperability fixture signs both).
- **Google Workspace** — the custom SAML app sends the primary email with
  the *unspecified* format by default; set the Name ID format to
  *Persistent* and map the Name ID to an immutable attribute (an employee
  ID, for instance), since email addresses can be renamed and reassigned.
- **Shibboleth IdP** — it sends transient NameIDs unless a persistent
  NameID generator (computed or stored IDs, see `saml-nameid.properties`
  and `saml-nameid.xml`) is configured, and selects the format from the
  AuthnRequest's NameIDPolicy, the SP metadata and the relying party's
  `nameIDFormatPrecedence`. Without a persistent generator, a connection
  requesting the persistent format gets an error status
  (`InvalidNameIDPolicy`).

### Browser binding, CSRF and replay

- **Login CSRF by response injection.** `BeginLogin` binds the
  transaction to the browser with a `__Host-samlsp` cookie (`Secure`,
  `HttpOnly`, `Path=/`, no `Domain`): the prefix keeps sibling subdomains
  and network attackers from planting it. It is `SameSite=None` because the
  IdP's POST to the ACS is a cross-site navigation that would not carry a
  `Lax` or `Strict` cookie. A response is accepted only for the transaction
  of the same browser, and its signed `SubjectConfirmationData` must answer
  that transaction's request ID (errata E90). An attacker's own valid
  response posted into a victim's browser is therefore refused, whatever
  cookies a sibling host tossed (browser suite, BR3 and BR4). Some legacy
  browsers (Safari on iOS 12 and macOS 10.14, Chrome 51–66) mishandle
  `SameSite=None`: their logins fail with `ErrMissingBrowserBinding`.
- **The ACS must be exempt from the application's CSRF protection**: the
  POST comes from the IdP's page. The binding cookie and `InResponseTo` are
  its CSRF defense.
- **RelayState is never a URL.** It is a random handle; the return target
  stays server-side in `LoginOptions.AppState`, and the library never
  redirects. An application redirecting to its AppState after the login
  must accept local paths only, with an allowlist rather than a cleanup:
  one leading `/` and no `//`, RFC 3986 path and query characters only — no
  control character, white space, `\` or non-ASCII byte — and still a local
  path once percent-decoded. Browsers drop TAB, LF and CR inside a URL and
  read `\` as `/`: `/\t/evil.example` is `//evil.example`, another origin.
  `safeReturn` in `examples/saml-sp` implements this.
- **Unsolicited responses are refused**: IdP-initiated SSO cannot be bound
  to a browser (Profiles §4.1.5, errata E90).
- **Leaked in-flight requests.** The binding proves that the browser
  posting a response started the login, not that the IdP's page posted it.
  The IdP redirect URL carries the request ID (in `SAMLRequest`) and the
  RelayState handle: whoever learns it while the login is pending — browser
  history, a proxy or server log, a shared screen — can sign in at the IdP
  as herself, get the response to the victim's request and auto-post it
  from a page the victim visits; the victim's browser attaches its
  `SameSite=None` cookie and ends up signed in as the attacker. The same
  page can post a forged response that burns the victim's login (see
  *Single use*). `Connection.ResponseOrigins` (opt-in) closes both: the
  request's single `Origin` header (Fetch §3.2) — or, from a browser that
  sends none, its `Referer`'s origin — must be one of the IdP's origins,
  before the transaction is touched (`ErrOriginMismatch`). It is off by
  default because browsers send `Origin: null`, which an attacker's page
  can produce too and which is therefore refused, from a page whose
  Referrer-Policy is `no-referrer` (or `same-origin`, cross-origin), from a
  sandboxed page, and after any cross-origin redirect before the POST.
  Keycloak's default realm sends `Referrer-Policy: no-referrer` from its
  POST page; a realm header of `strict-origin-when-cross-origin` makes
  browsers send its origin (Keycloak live run, K8). Without the option, keep
  `TransactionTTL` as short as the IdP interaction allows, never log full
  IdP redirect URLs, and show the signed-in account after a login.
- **Single use.** `CompleteLogin` consumes the transaction atomically — one
  winner across instances — once the response passed the browser binding,
  the transaction checks, the status and the Response `InResponseTo`, and
  before any signature verification: a login allows one verification, and a
  response refused from then on ends it (`ErrTransactionConsumed` for any
  later POST; the span carries `samlsp.transaction_consumed`). Only the
  browser holding the binding cookie gets that far. The assertion then goes
  to the replay cache (Profiles §4.1.4.5), keyed by a digest of the
  connection, the issuer and the assertion ID and retained until the
  assertion can no longer be accepted (the earlier of
  `SubjectConfirmationData NotOnOrAfter` + skew and the transaction expiry,
  plus one minute). Both stores must be shared by every instance, and read
  from the primary.
- **Transaction integrity.** Each stored transaction carries an
  HMAC-SHA256 under a server-held key (`Config.TransactionKeys`, required)
  over its ID, browser binding, payload and expiry, verified in constant
  time before any stored field is used: a writer of the store can neither
  rebind a pending login to another browser or request nor relax its
  `ForceAuthn` or requested context (`ErrTransactionIntegrity`). The stores
  are trusted for availability and single consumption only: give the SP
  least-privilege access — a Redis ACL limited to its key prefix, a
  database user limited to its two tables. The keys are the records' only
  integrity protection: use keys distinct from the OpenID Connect client's
  and the session's, and replace a leaked one at once.
- **`BeginLogin` writes to the store without authentication**: rate-limit
  the login entry point, and the ACS per client too — a POST that passes
  the binding check costs one verification.
- **Gate login initiation.** A page of another site can send the user's
  browser to the login entry point (forced login initiation, a form of
  login CSRF): with an IdP session alive, the user is logged in, or
  switched to another session, without asking. Through a connection whose
  IdP the attacker controls, typically her own tenant, the victim ends up
  in the attacker's account. The browser binding cannot tell: the victim's
  browser started that login. Start logins only from same-origin
  navigations — Fetch Metadata's `Sec-Fetch-Site` is `same-origin` or
  `none` (typed URL, bookmark); refuse `cross-site` and `same-site` — or
  from a CSRF-protected POST. `examples/saml-sp` does the former and
  also refuses a request without the header, which a login forced in a
  browser without Fetch Metadata would be: those browsers (Safari and iOS
  before 16.4) cannot sign in to it, the header reaches only https (or
  loopback) sites (Fetch Metadata §3), and `none` still admits a login
  forced through a link opened from another application. The browser suite
  (BR8) shows the refusals ([guide](saml-sp.md#5-sessions-and-logout)).
- **The ACS location is checked** (Core §3.2.2, Bindings §3.5.5.2): the
  request must have been received at the connection's ACS URL — the same
  escaped path, the same host (`r.Host`, never a forwarding header), no
  query string — and `Destination` (required on a signed Response) and
  `Recipient` must equal it. Behind a proxy that rewrites `Host`, forward
  the original, or pass `CompleteLogin` a copy of the request whose `Host`
  comes from the trusted proxy's header. A
  Success `Response` must carry `InResponseTo`, equal to the request ID.

### Time

- `ClockSkew` (3 minutes by default, 5 at most; errata E92) applies to every
  bound: an assertion is valid from `NotBefore − skew` and until
  `NotOnOrAfter + skew`, exclusive. `IssueInstant`s must lie between the
  transaction start − skew and now + skew; `ForceAuthn` requires an
  `AuthnInstant` after the transaction start − skew.
- goxmldsig checks the IdP certificate validity with gosaml2's single
  clock, which `samlsp` sets to `now − ClockSkew` so that gosaml2's own time
  checks are never stricter than those of `samlsp`. An IdP certificate is therefore
  accepted until `NotAfter + skew`, but only from `NotBefore + skew`: a
  certificate whose validity starts at a key rollover is refused during the
  first `ClockSkew`. Import new IdP certificates ahead of their use (errata
  E68: any listed key may sign).

### Identity

The IdP entity ID is a claim of the connection, not a global identity: in a
multi-tenant application, one tenant can configure an IdP whose entity ID
collides with another tenant's. Key external accounts on the connection ID
and the persistent NameID (with the issuer and the NameID qualifiers).
Never key them on a transient NameID or an email attribute, and never link
accounts by email automatically: an IdP vouching for an address says nothing
about the account another tenant's IdP vouches for. Encode the key without
ambiguity — a connection ID may contain any separator: `examples/saml-sp`
length-prefixes the connection ID, the issuer, the NameID qualifiers (absent
ones stand for the issuer and the SP entity ID), the format and the value.

### Resource limits

`MaxResponseSize` (256 KiB by default, 16 KiB to 1 MiB) bounds the ACS
request body — or, when the application parsed the form before calling
`CompleteLogin` (Go's own limit is 10 MB), the SAMLResponse value itself.
The response then passes a streaming lexical gate before anything builds a
tree: at most 1 MiB, 450
elements (`MaxResponseElements`, sized from goxmldsig's 1000-node
canonicalization budget; gosaml2 verifies up to about 500), 4096 tokens,
depth 64, 16 attributes and 16 namespace declarations per element, 32
in-scope prefixes, 8 KiB attribute values; no DTD, entity or processing
instruction, and only namespace-well-formed names (Namespaces in XML 1.0
§3, §7: no empty prefix or local part, which encoding/xml would keep whole
in no namespace). Measured on an Apple M-series machine (Go 1.26): a typical
login costs about 1.1 ms and 1.1 MB; the most expensive response within the
default limits about 25–33 ms and 21–28 MiB, about 61–69 ms and 33–43 MiB at
the 1 MiB ceiling; inputs aimed at amplification are refused within 10 ms
and 9 MiB. When a signature carries no KeyInfo and the connection trusts
several certificates, each certificate tried re-runs the whole verification:
at most the three most recent valid ones are tried, the one that verified
the connection's last such signature first, which bounds that case to three
times the costs above — once per login, since the transaction is consumed
before the verification. The pre-check runs twice on a response whose
certificate-less `KeyInfo` it cuts, within the same limits and before any
store access. A response carrying hundreds of group
memberships exceeds the element cap (`ErrResponseTooLarge`): filter the
groups the IdP releases to the application rather than raising limits.

### Metadata retrieval

`FetchIdentityProviderMetadata` downloads an IdP's metadata once, and a
`MetadataSource` keeps it current for a `ConnectionResolver`. Both treat the
network as hostile:

- **The URL is configuration** — the application's, or a tenant
  administrator's — and never a value read from a SAML message or a
  request. It must be https (http only with `Outbound.AllowHTTP`), without
  credentials or fragment. No response content triggers a fetch: an
  unknown `KeyInfo` certificate fails the login, it does not refresh the
  metadata, so an attacker cannot make the SP fetch.
- **Requests go through `outbound`** (see
  [Outbound requests](#outbound-requests-ssrf)): publicly routable
  destinations only, judged on the address dialed, no redirect, no proxy,
  no cookie, no credentials, 10 s, and the smaller of `MaxSize` (1 MiB) and
  the policy's body limit, counted after decompression. When the policy
  allows redirects, none may leave the configured URL's origin (scheme,
  host and port): keys can only come from that origin. A host or port that
  `outbound` always refuses (`127.1`, a trailing dot, an underscore, port
  0) fails at construction with `ErrInvalidConfig`. Only a 200 answer is
  read; no error carries the response body. An on-premises IdP needs its
  subnet in `Outbound.AllowedPrefixes`; pin its host in `CheckURL`, and its
  private CA in `RootCAs`.
- **Trust** rests on TLS to the configured origin and on the pinned entity
  ID (`MetadataSourceConfig.EntityID` is required): a document of another
  entity is refused. `FetchOptions.EntityID` is optional, to discover a new
  IdP's entity ID: pin it whenever a fetch replaces keys already
  configured. Keys and endpoints change only through a valid
  document of that entity fetched from that URL, so an IdP key rollover is
  picked up at the next refresh — announce the new key in the metadata
  before signing with it. Signed metadata is not supported: the embedded
  signature is ignored, and a federation aggregate, whose trust comes from
  its signature, must not be used as a source. Where TLS to the IdP's
  metadata host is not trusted enough, import the metadata out of band.
- **Bounded refresh**: at the document's `cacheDuration` (one hour when
  absent, the shortest interval for `PT0S`) clamped to `[MinRefresh,
  MaxRefresh]` (5 minutes, 24 hours by default), and when it expires;
  concurrent callers share one fetch, which runs detached from the caller
  that started it and is bounded by the outbound timeout; fetches are
  spaced by `RetryInterval` (one minute) after a failure or an early
  expiry. A due refresh never delays a login while a usable document is
  cached: it runs in the background, and only a caller with nothing usable
  waits for it, so a slow or hostile metadata endpoint cannot put its
  latency on the login path. While refreshes fail, the last good
  document is served for at most `MaxStale` (7 days) after it was fetched
  and never past its `validUntil` (Metadata §4.3.2, errata E94); then
  logins fail closed with `ErrMetadataExpired`. Failures surface as
  `ErrMetadataUnavailable` (the `outbound` errors stay matchable),
  `ErrInvalidMetadata` or `ErrMetadataExpired`; a resolver returning them
  makes `BeginLogin` and `CompleteLogin` fail as infrastructure errors, not
  rejections.

### Dependencies

XML signature verification and canonicalization are never implemented in
this repository. They come from:

| Module | Minimum | Advisories considered |
| ------ | ------- | --------------------- |
| `github.com/russellhaering/goxmldsig` | v1.6.1 | GHSA-479m-364c-43vc (CVE-2026-33487, signature bypass, fixed in v1.6.0); GHSA-qhrp-hfff-vphr (quadratic memory in SignedInfo canonicalization, fixed in v1.6.1); older bypasses (CVE-2020-15216) |
| `github.com/russellhaering/gosaml2` | v0.12.0 | GHSA-66r8-42f7-4q74 (allocation amplification in the round-trip validation, fixed in v0.12.0); GHSA-5hj8-q7fv-qrj6 and GHSA-hwqm-qvj9-4jr2 (decryption panics: unreachable, encrypted content is refused first); GHSA-pcgw-qcv5-h8ch and GHSA-vv4x-5gvr-chh8 (unsigned logout messages: Single Logout is not used); GHSA-6gc3-crp7-25w5 (CVE-2023-26483, DEFLATE bomb: POST bodies are never inflated, and gosaml2's own limit is set to one byte) |
| `github.com/beevik/etree` | v1.8.1 | GHSA-qm2r-qg5g-crr3 (stack overflow on deep nesting, also bounded by the depth cap), GHSA-2mj8-7fmf-pr7x, GHSA-f965-f62m-c42m, GHSA-x27v-cqwr-28jx — all fixed by v1.7.1 |
| `github.com/mattermost/xml-roundtrip-validator` | v0.1.0 | none (used by gosaml2 to refuse documents `encoding/xml` does not round-trip) |

gosaml2 is maintained, verifies before it decodes, and decodes from the
verified bytes; `samlsp` uses it only to encode AuthnRequests and to verify
responses, never its `RetrieveAssertionInfo` (which reports audience and
time problems as warnings). `github.com/crewjam/saml` was not chosen: it had
critical signature bypasses (CVE-2020-27846, and CVE-2022-41912 with several
assertions) and is less actively maintained; it serves only as the
independent IdP of the private interoperability tests. A future goxmldsig or
gosaml2 upgrade must keep `TestGosaml2TraversalBudgetIsPinned` green: the
element cap depends on goxmldsig's traversal budget.

## Sessions

`session` issues a **stateless encrypted cookie** — there is no server-side
session store to compromise or scale.

- **Confidentiality + integrity** — the cookie payload is sealed with
  AES-256-GCM (AEAD): tampering fails decryption, it is not merely detected.
- **Keys** — `NewCodec` requires keys of at least 32 bytes from a
  cryptographic source (`openssl rand -base64 32`, `crypto/rand`) and
  refuses shorter keys and buffers that were never filled; it cannot tell a
  random key from a 32-character passphrase, so never use one. Each key is
  expanded with HKDF-SHA256 under a label of its own (RFC 5869), so a secret
  reused elsewhere never yields the same AES key.
- **Binding** — the AEAD associated data binds every cookie to the format
  version, the cookie name and an optional purpose (`WithPurpose`): a cookie
  minted for another cookie name, application or path that shares the keys
  never opens (NIST SP 800-38D).
- **Key rotation** — the `Codec` accepts an ordered key list. New cookies
  are sealed with the first key; decryption is attempted against every key,
  so a key can be retired gracefully, and `Touch`/`Rotate` re-seal a cookie
  with the active key.
- **Absolute lifetime** — a session expires at the earlier of the
  `ExpiresAt` its cookie carries and `CreatedAt + TTL` of the reading
  `Manager`: lowering the TTL applies to issued cookies at once, raising it
  extends none, and neither `Rotate` nor `Touch` ever extends a session.
  The idle timeout slides only when `Touch` rewrites the cookie.
- **Revocation** — the cookie is stateless, so `Logout` only deletes the
  browser's copy. To revoke server-side — a stolen copy after logout, every
  session of a user after a password change — register `WithValidator`
  against a store of yours (a deny-list of session-ID fingerprints kept until
  the session's deadline, or a "valid since" time per user); cache its
  lookups. A validator error wrapping `security.ErrUnavailable` answers 503,
  so an outage of that store never signs everyone out.
- **Cookie attributes** — defaults are conservative: `Secure=true`,
  `HttpOnly=true`, `SameSite=Lax`, and the name `__Host-session`: a
  `__Host-` cookie is Secure, has `Path=/` and no `Domain`, so a sibling
  host cannot plant a cookie that shadows it (cookie tossing,
  draft-ietf-httpbis-rfc6265bis §4.1.3.2). When the configuration cannot
  satisfy that prefix the default name falls back to `__Secure-session`
  (a `Domain` or another `Path`) or `session` (`WithSecure(false)`, local
  plain-HTTP development only). `NewManager` refuses at start-up a
  configuration browsers would refuse: an invalid name, path or domain, a
  `__Host-`/`__Secure-` name whose rules the attributes break (prefixes
  matched case-insensitively, like browsers do), `SameSite=None` without
  `Secure`.
- **Shadowing cookies** — when a request carries several cookies of the
  session's name and more than one opens as a valid session, it has no
  session: a tossed cookie can deny a session (until it expires), never
  swap it. Copies of one session count as several — they can differ, as a
  copy planted before a sign-in without `Rotate` does — while expired or
  undecodable ones do not count. With the default `__Host-` name no other
  host can toss one at all. Stale duplicates have the same effect: after
  changing `WithDomain` or `WithPath` while the cookie keeps its name,
  browsers keep the cookie of the earlier `Domain` or `Path` next to the
  new one, so clear each old variant once with `Max-Age=0` — a
  `Set-Cookie` of the same name with the old `Domain` and `Path` (in Go,
  `http.Cookie{…, MaxAge: -1}`).
- **Cookie only** — the `Manager` reads the session from the request's
  `Cookie` header field, through `httpsec.Carrier.CookiesNamed`, never from
  the URL nor from a header named like the cookie: a link carrying a session
  value cannot log a browser into another account.
- **Session fixation** — call `Manager.Login` at sign-in: it mints a fresh
  session (new ID, new CSRF token, new lifetime) and replaces the previous
  one. `Manager.Rotate` mints a new ID and CSRF token within the same
  session — after a step-up — and keeps its creation time and deadline. The
  ID never appears raw in a span — only a SHA-256 fingerprint.
- **Values** — numbers come back as `json.Number` (read integers with
  `Session.GetInt64`): a 64-bit ID never loses precision through a float64.
  Treat a value that is present but unreadable as a refusal, not as absent.
- **CSRF** — the synchronizer-token helper (`CSRFToken` / `VerifyCSRF`)
  compares tokens in constant time, but it is a check, not a policy: call
  `VerifyCSRF` on every state-changing request a cookie session
  authenticates, never change state on GET, and put `net/http`'s
  `CrossOriginProtection` (Sec-Fetch-Site and Origin checks) in front of the
  handlers. `SameSite=Lax` does not stop same-site requests from a sibling
  subdomain. The cookie is `HttpOnly`, but the token is rendered into the
  page: an XSS reads it — no CSRF defense survives XSS.
- **Sign-in form** — protect it too, against login CSRF, with the token of a
  session opened for the form (`Login` with a nil principal) on a
  **dedicated `Manager`**: its own cookie name and purpose, a short TTL
  (`WithCookieName("__Host-signin")`, `WithPurpose("sign-in form")`,
  `WithTTL(15*time.Minute)`), read by no `Extractor`. On the `Manager`
  behind the Engine, the Engine would extract that subject-less session on
  every request and the `PrincipalLoader` refuse it: every page, the
  sign-in form included, would answer 401. Do not work around that by
  mapping a session without a subject to a principal — anonymous or guest:
  the `Authenticator` would return an **authenticated** value, which
  `voter.Authenticated` grants. The session-web example shows the pattern.
- **Size** — the whole session is JSON-encoded into the cookie, and browsers
  ignore a cookie whose name and value exceed 4096 bytes (rfc6265bis §5.6):
  `Login`, `Touch` and `Rotate` refuse it with `ErrCookieTooLarge` instead
  of losing the session silently. Keep `Values` small.
- **Key usage** — nonces are random (96 bits), and NIST SP 800-38D §8.3
  limits one key to 2^32 seals: every `Login`, `Touch` and `Rotate` is one.
  Rotate the active key well before that volume (about 50 days at 1 000
  cookie writes per second), and do not `Touch` on every request.

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
  its fields, which `Complete` verifies before using any stored field: a
  transaction altered in the store — a stripped `max_age` or `acr_values`,
  a rewritten `AppState` or redirect URI — fails its login
  (`ErrTransactionIntegrity`). The MAC key is
  HMAC-SHA256(transaction key, `"oidcclient/integrity/v2"` ‖ binding
  secret): it needs both the binding secret — which the user agent of the
  login holds — and a server-held transaction key
  (`Config.TransactionKeys`) the store never sees, so an attacker who can
  write to the store cannot forge it even for a login it runs with its own
  browser. The store is trusted for availability and single consumption
  only. The transaction keys are secrets like a session key: 32 bytes or
  more from a cryptographic source, shared by every instance serving
  callbacks, never logged (`Config` and `*Client` redact them with every
  `fmt` verb and in `slog`). Rotate them in three steps — add the new key last on every
  instance, move it first, remove the old one once `TransactionTTL` has
  elapsed: the first key protects new transactions, every key is accepted.
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
  the configured issuer's `jwks_uri` only (`jku`, `x5u`, `jwk` and `x5c`
  are refused, see below) through a bounded cache that refetches once, rate
  limited, for an unknown key, and never on a bad signature from a known
  one; `iss`,
  `aud` (further audiences only when trusted), `azp`, `exp`/`iat`/`nbf`
  within a bounded skew, `nonce`, `auth_time` against `max_age`, `acr`
  against the requested `acr_values`, and `at_hash` when present. Before
  go-jose parses it, the JOSE header must be strict JSON of at most 4 KiB
  without `jku`, `x5u`, `jwk` or `x5c` (OpenID Connect Core §2: ID Tokens
  SHOULD NOT use them): go-jose parses `jwk` and `x5c` before any check,
  and up to v4.1.5 validated an embedded RSA private key at a cost cubic in
  its size, so a hostile provider could make each login cost hours of CPU
  (GHSA-mgcc-cww5-fp2q). RFC 7515 §4 would let a recipient ignore these
  members; refusing them is a local policy: providers that send them —
  Cloud Foundry UAA and SAP BTP XSUAA put `jku` in their headers — are not
  supported. Every JSON document is decoded strictly: duplicate member
  names, two names
  that differ only by case, invalid UTF-8 and unpaired surrogates are
  refused, so no decoder can pick between two members. A lone member whose
  name differs from a known claim only by case (`EMAIL_VERIFIED`) is
  another claim, which OpenID Connect Core §2 and RFC 7519 §4 require
  ignoring — yet `encoding/json`, matching struct fields
  case-insensitively, reads it as `email_verified`. An honest provider
  releasing attribute names its users choose can emit one. Decode claims with
  `Identity.DecodeClaims` / `UserInfo.Decode` or into a map, and read the
  validated values (`Subject`, `Audience`, `AuthTime`, `ACR`, `AMR`) from
  the `Identity` fields, never again from `Claims`.
- **Identity** — the verified identity is the issuer and subject pair
  (Core §5.7). Link accounts on (connection or tenant, issuer, subject);
  never on email, phone or username, which another subject or provider can
  assert. For Microsoft Entra ID, configure the tenant's own issuer: the
  templated multi-tenant issuers are refused.
- **Cookies** — binding cookies are `__Host-` (Secure, Path=/, no Domain:
  a sibling subdomain cannot plant one), HttpOnly, named after the state so
  parallel logins coexist, capped at four per browser, and deleted by the
  callback. The cap counts and expires only names of their shape — the
  prefix and 16 lowercase hex digits — never the application's own cookies
  sharing the prefix. SameSite is Lax for the `query` response mode — the callback
  is a top-level GET — and None for `form_post`, whose cross-site POST
  carries no Lax cookie; an opt-in headless-Chrome test checks both.
  `InsecureCookies` drops Secure for local http development only, and is
  refused with `form_post`.
- **CSRF** — exempt the callback route from CSRF middleware in `form_post`
  mode: the cross-site POST is the protocol, the binding cookie its
  defense. Start logins on a user action from the application's own
  origin (a POST behind `http.CrossOriginProtection` or a CSRF token) and
  rate limit them: each start writes a transaction, and a non-browser
  client passes the cross-origin protection. `examples/oidc-client` limits
  each client (an IPv4 address, an IPv6 /64) and each network (an IPv4
  /24, an IPv6 /48) and bounds its in-memory store (`memory.WithCapacity`);
  a flood from enough networks still fills the store, which refuses new
  logins until transactions expire — limit at the edge as well.
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
  generic message. The provider-controlled text an error echoes (an issuer,
  a media type, a redirect target, a JOSE header member, a query parameter
  name, the debug data of an HTTP/2 GOAWAY ending a response) is Go-quoted
  — control characters and invalid UTF-8 escaped — then cut to about 256
  bytes.
- **Tokens** — token and UserInfo requests never follow redirects
  (discovery and JWK Set requests only within the origin requested);
  `UserInfo` sends an identity's access token only to the UserInfo
  endpoint of the connection that issued it, and returns claims only when
  their `sub` is the identity's. Every `fmt` verb and `slog` redact
  secrets (`%p` of a non-pointer value excepted: fmt prints the fields
  before any method), and so does `encoding/json` for `Config`,
  `AuthRequest` and `Callback` — which matters to `slog`'s JSON handler,
  which encodes a nested value with `encoding/json`. `Identity` and
  `Tokens` deliberately encode their tokens (applications persist them),
  `UserInfo` its claims: never log them nested in another value.
- **Caveats** — sending `acr_values` makes `acr` required, among the
  requested values; a public client (`none`) requires the provider to
  advertise S256. `github.com/coreos/go-oidc` was evaluated and rejected:
  its verifier skips nonce, azp, iat, `typ`, auth_time and acr, and its key
  set refetches on every failure without rate limit (see the package
  documentation of `oidc/client`).

## OpenID Connect: protocol validation vs application policy

`oidc/provider` and `oidc/client` validate the protocol — every rule their
feature matrices list ([oidc-provider.md](oidc-provider.md),
[oidc-client.md](oidc-client.md), [oidc-conformance.md](oidc-conformance.md)).
What the protocol leaves open is policy, and stays with the application:

| Concern                    | The library validates                                                                                                    | The application decides                                                                                      |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------ |
| Tenants and connections    | issuer equality, a transaction bound to its connection, issuer, client and redirect URI, RFC 9207 `iss`; realms and issuer-bound clients (provider) | which connections exist, routing a login start to one, distinct redirect URIs, which issuers tenants may configure |
| Identity and accounts      | the (issuer, subject) pair, UserInfo `sub` equality                                                                      | account linking (on connection, issuer, subject), just-in-time provisioning, link flows bound to a session    |
| Authentication strength    | `max_age`/`auth_time`, `acr` among `acr_values` (client); freshness, essential `acr` (provider)                          | the acr levels required, step-up and MFA, AMR policy, the login pages                                         |
| Consent                    | released claims, a scope that only narrows, `offline_access` only with the decision's grant — `prompt=consent` for OpenID requests — or the application's policy, for every request | the consent pages and records, the offline-access policy                                                      |
| Sessions                   | no session of another realm or end-user, no state revealed under `prompt=none`                                           | session lifetime, a fresh session after each login, sign-out (no logout specification is supported)          |
| Account disabling          | `ErrUnknownSubject` stops every grant at its next use (exchange, refresh, UserInfo)                                     | disabling accounts, revoking their token families for immediate effect                                        |
| Keys                       | rings validated on every use, public keys only published; the client's bounded JWK Set cache                             | key custody (KMS), the rotation schedule, the response to a leaked key                                       |
| Outbound requests          | https and public destinations only by default                                                                            | exemptions for on-premises providers (`AllowedPrefixes`, `CheckURL`, `RootCAs`)                               |
| Login transactions         | browser binding, integrity, single use                                                                                   | the store's deployment, the transaction keys (generation, sharing, rotation), purging                        |
| Abuse and audit            | nothing beyond the protocol's refusals                                                                                   | rate limiting of login starts and endpoints, audit logs (`OnError` sinks), monitoring                         |

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
  requests (token, UserInfo) never follow redirects. `oidc/client`'s
  discovery and JWK Set requests, `jwtsec.NewRemoteJWKS`'s JWK Set requests
  and `saml/sp`'s metadata requests, whose answers are trusted because of
  the origin they come from, never follow a redirect to another origin
  (scheme, host and port), whatever `MaxRedirects` allows: after such a hop
  another server would get its keys trusted — for discovery, by merely
  writing the expected issuer.
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

## Credentials in header fields only

`httpsec.Carrier.Get`/`Values` (and the gRPC and ConnectRPC carriers) read
header fields only: the Basic and Bearer extractors accept credentials from
the `Authorization` field alone, never from the URL query string (RFC 6750
§5.3: tokens in URLs leak through logs, `Referer` and browser history) nor
from a cookie named like the field (an ambient credential a cross-site
request would carry).

## Extractor order

The `Engine` tries its extractors in order and the first one that finds a
credential wins (as in Spring Security's filter chain): a deliberate design,
not a fallback between schemes. Put the header-based extractors (bearer,
basic) before the session extractor: a browser attaches cookies to
cross-site requests by itself — `SameSite=Lax` still sends them on
top-level GET navigations — but never an `Authorization` header, so an
engine that accepts a cookie session authenticates requests an attacker's
page can trigger. Protect every state-changing endpoint reached with a
cookie session against CSRF, and prefer one engine per audience (browser
pages, APIs) so that an API never authenticates an ambient cookie.

## Attempt limiting

`security.AttemptLimiter` is the online-guessing control of NIST SP
800-63B-4 §3.2.2 and the brute-force protection RFC 6749 §2.3.1 and §4.3.2
require of the OAuth 2.0 endpoints that check a secret. A verifier calls
`Allow` before it checks the credentials and `Record` with the outcome
after:

- **Reserve, then settle — once per attempt.** One `Allow` per attempt,
  with one key: the limiter charges every budget it keeps for that key, the
  per-source one included. `Allow` counts the attempt as failed until
  `Record` settles it, so a burst of concurrent guesses cannot all pass the
  check before the first failure is known. Concurrent legitimate attempts
  hold reservations too: size the allowance above a client's concurrency,
  or authenticate once and carry a session or a token. A lost `Record`
  keeps the charge: it errs toward limiting.
- **Fail closed.** A refusal wraps `ErrTooManyAttempts`: HTTP 429 Too Many
  Requests with `Retry-After` and `Cache-Control: no-store` (RFC 6585 §4),
  gRPC and Connect `ResourceExhausted`. A limiter that cannot decide (a
  shared store is down) returns an error wrapping `ErrUnavailable` — 503 —,
  and any other error refuses the attempt too.
- **The key.** `AttemptKey` names the credential type (`Realm`), the
  claimed identity (`Subject`) and the client address (`Source`). The
  subject is client input — even a password typed in the username field —:
  the key prints it `REDACTED`, and `throttle` stores only a hash of it.
  Normalize the subject the way your account store does (case, Unicode
  form): every variant counted apart multiplies the allowance.
- **The source.** `httpsec`, `grpcsec` and `connectrpcsec` store the
  transport peer as the client address (`security.ClientAddrFromContext`).
  Behind a reverse proxy every request comes from the proxy: store the
  client address it forwards with `security.WithClientAddr` in a middleware
  or interceptor that runs before the adapter — taken from the hop your
  trusted proxy appended (the right-most `X-Forwarded-For` entry it wrote,
  or RFC 7239 `Forwarded`), never the left-most entry, which the client
  chooses. Outside the adapters (a form login calling `Authenticate`, an
  OAuth 2.0 endpoint), read the address the same way: from the context
  first (`security.ClientAddrFromContext`), then from the transport peer
  (`security.ParseClientAddr(r.RemoteAddr)`).

`throttle.MemoryLimiter` charges every attempt to three budgets, checked
and charged together, a refusal charging none: per subject and source (10
failures, then one every 90 s), per subject from every source (100, then
one every 36 s — the per-account limit) and per source against every
subject (100, then one every 9 s — spraying). IPv6 sources count per /56
(RFC 6177), IPv4 per address; an unknown source only meets the per-subject
budget. A success clears its own (subject, source) failures and refunds its
own charge elsewhere — it does not reset the per-subject budget, which
other sources keep spending. The table holds at most `MaxKeys` entries
(100 000, about 12 MiB); when it is full the least throttled entry is
forgotten, never one of the attempt being charged.

Trade-offs to choose knowingly:

- The per-subject budget lets a distributed attacker lock an account out
  while the attack lasts. Keep it for passwords (NIST requires a
  per-account limit); turn it off (`Limit{Failures: throttle.Unlimited}`)
  for credentials that cannot be guessed, such as OAuth 2.0 client secrets,
  whose client identifiers are public. Use one limiter per credential type.
- The per-source budgets are shared by every client behind one IPv4
  address or inside one IPv6 /56: a NAT, a proxy, providers that number
  customers inside one /56, a NAT64 or SIIT translator (store the embedded
  IPv4 address with `security.WithClientAddr`).
- An unknown source meets only the per-subject budget: with it off, `Allow`
  refuses the attempt as unavailable (503) — supply the client address.
- It is a throttle, not the lock-out of NIST §3.2.2 ("no more than 100 …
  by disabling that authenticator"), and it lives in one process. A global
  or permanent limit needs an `AttemptLimiter` over a shared store, or an
  account flag your loader reports locked.

## Authorization

Authorization follows Spring Security's voter model, and fails closed:

- **The attributes are the policy.** Each voter votes only on the
  attributes whose family and value it supports: `HasRole("ADMIN")` votes
  on `security.Role("ADMIN")` and abstains on `security.Role("USER")`, so a
  decision manager shared by several routes grants each route only what it
  asks for. `voter.Authenticated()` and `voter.Anonymous()` vote only on
  `security.IsAuthenticated` / `security.IsAnonymous`: list the state you
  require among the route's attributes.
- **Separate namespaces.** A role is the authority `ROLE_<name>`
  (`security.RolePrefix`), a scope the authority `scope:<name>`
  (`security.ScopePrefix`, one scope per authority), anything else a plain
  authority matched verbatim by `HasAuthority`: a scope a client obtained
  can never pass for a role.
- **No requirement is ignored.** A decision is denied when one of its
  attributes is supported by no voter of the decision manager, when there
  is no attribute, and when there is no voter — whatever the strategy, the
  tie-break and the abstain fallback: `WithAbstainFallback` only decides
  for custom voters that support an attribute and abstain.
- **Composites.** `voter.And` grants only when every inner voter grants — an
  inner voter whose attribute the route does not list makes it deny, so list
  one attribute per inner requirement. `voter.Not` never turns the refusal
  of an unauthenticated principal into a grant: `Not(HasRole("BANNED"))`
  admits authenticated principals without the role, not anonymous callers.
  A `Role("X")` attribute is decided by every voter that supports it,
  negated ones included: a decision manager holding `Not(HasRole("X"))`
  grants a `[Role("X")]` route to the authenticated principals *without*
  X, and next to a positive `HasRole("X")` voter the affirmative strategy
  grants it to those *with* X too. Keep a negated policy in its own
  decision manager, used only by the routes it was written for.
- **Strategies.** Affirmative grants on one satisfied attribute (OR);
  unanimous requires every voting voter to grant (AND across voters), but a
  multi-name voter such as `HasAnyRole` grants when the principal holds any
  of the requested names — use one voter per role, or `voter.And`, for an
  AND of roles.

## Transport error mapping

Error mappers return terse, code-first responses, classified once by
`security.ErrorClass` — joined errors included — so a refusal by one
authenticator is never masked by another one's lack of support, and an
outage never reads as a verdict on the credentials:

| Class | HTTP | `WWW-Authenticate` (scheme S, realm R) | gRPC / ConnectRPC |
| --- | --- | --- | --- |
| `invalid_request` (e.g. repeated `Authorization`) | 400 | Bearer: `Bearer realm=R`; + bearer token sent: `error="invalid_request"` | `InvalidArgument` |
| `unavailable` (`ErrUnavailable`) | 503 | Bearer: `Bearer realm=R` | `Unavailable` |
| `token_expired`, `token_not_found`, `client_secret_mismatch`, `invalid_credentials` | 401 | `S realm=R`; Bearer + bearer token sent: `error="invalid_token"` (RFC 9068 §4) | `Unauthenticated` |
| `authentication_required`, `unsupported_credential` | 401 | `S realm=R` — no error code (RFC 6750 §3.1) | `Unauthenticated` |
| `insufficient_scope`, `access_denied` | 403 | `S realm=R`; Bearer + bearer token sent: `error="insufficient_scope"` | `PermissionDenied` |
| `no_extractor`, `_OTHER` (no sentinel: a broken contract) | 500 | Bearer: `Bearer realm=R` | `Internal` |

A ConnectRPC error travels over HTTP with the status of the HTTP column, and
the `connectrpcsec` default mapper puts the same `WWW-Authenticate`
challenge in its metadata — sent as response headers on unary calls — so
every Connect 401 carries one.

Every 401 carries a challenge with a realm (`api` by default; RFC 9110
§11.6.1, RFC 7617 §2, RFC 6750 §3), a Basic one also `charset="UTF-8"`
(RFC 7617 §2.1), and the realm is sent as an RFC 9110 quoted-string — a
realm a quoted-string cannot carry is refused at startup. A Bearer resource
challenges every refusal, 400 and 5xx included: RFC 6750 §3 requires the
challenge whenever the request carried no access token that enables
access. An unauthenticated
principal refused by `httpsec.Authorize` is asked to authenticate (401), an
authenticated one refused (403) (RFC 9110 §15.5.2, §15.5.4); `Authorize`
answers with the challenge of the `Middleware` in front of it. The RFC 6750
error codes are sent only when the request carried a bearer token. The
`error_description` is a fixed string per code: the response never says why
authentication failed. Clients are expected to branch on the status and the
code, not parse the message. The gRPC messages are one fixed string per
code (`unauthenticated`, `permission denied`, …). gRPC clients commonly
retry `Unavailable`: wrap `security.ErrUnavailable` only for a transient
dependency failure.

Install the gRPC interceptors for both RPC kinds — `grpcsec.ServerOptions`
and `grpcsec.AuthorizeServerOptions` return the unary and stream chains
together: chaining only unary interceptors leaves every streaming RPC (the
health service's `Watch`, server reflection, your own streams)
unauthenticated.

## Observability

No secret is ever placed on a span attribute or log line, and the core
spans record the class of an error (`security.ErrorClass`), never its text,
which can hold user input such as a typed username. See
[observability.md](observability.md) for the secrets policy and the full
span catalog.

## Toolchain and supply chain

- **Go toolchain.** Every module requires Go 1.27.3 (its `go` line). The
  library cannot be built with a toolchain carrying the standard-library
  advisories fixed up to go1.27.3: HTTP/2 server crashes and request
  smuggling in `net/http`, `crypto/tls`, `encoding/asn1`, `net/url`,
  `encoding/xml`, and the distrust of compromised intermediate certificates
  in `crypto/x509` (GO-2026-6809), which every TLS client path of the
  library reaches. Build and ship with the latest Go patch release, and run
  `govulncheck` on your application: which advisories matter depends on the
  code you call.
- **Vulnerability scanning.** The `govulncheck` workflow scans every module
  on every change and weekly, and it must be green on the commit of a
  release ([releasing.md](releasing.md)):
  - govulncheck, outside the workspace (each module's own requirements,
    tests included), against the Go vulnerability database;
  - OSV-Scanner, against the OSV database, which adds the GitHub-reviewed
    advisories (GHSA) before the Go database imports them, and the records
    it withdrew. An advisory without symbol data fails whenever a required
    version is affected; the others go through Go call analysis.

  The release workflow scans the released module with both and never
  publishes over a failing scan. Known and not reachable: GO-2026-5932
  (`golang.org/x/crypto/openpgp` is unmaintained, no fix) is reported at
  module level, and by OSV-Scanner as uncalled, for the modules that
  require `golang.org/x/crypto`; none imports `openpgp`. Accepted reachable
  advisories (ID, reason, owner, review date): none. No scanner covers the
  security advisories a dependency publishes in its own repository and
  GitHub never reviews, in practice those without a CVE:
  [releasing.md](releasing.md) lists the ones known and the manual check
  before a release.
- **Dependencies.** Dependabot proposes version updates for every module
  after a 7-day cooldown (security updates are not delayed). The
  development tools (golangci-lint, govulncheck, goveralls, mockery,
  osv-scanner) are pinned in modules of their own under `tools/` and never
  reach a library's module graph. They run in CI only, checksum-verified by
  their `go.sum`, with a read-only token and no secret; osv-scanner alone
  brings about 200 third-party modules into the jobs that build the tools,
  and the release workflow builds them without a cache.
- **CI and releases.**
  - The workflows run with a read-only token by default (only the release
    publish job gets `contents: write`), every action is pinned to a full
    commit SHA, and checkouts keep no credentials.
  - A release is verified with a read-only token (`scripts/release-check.sh`,
    build, test, lint, govulncheck, OSV-Scanner) before a separate job
    publishes the GitHub release, without checkout or third-party code.
  - Module tags are not signed: verify the modules through the Go checksum
    database (`sum.golang.org`), as `go get` does by default. Never set
    `GOSUMDB=off`, and never let a `GOPRIVATE` or `GONOSUMDB` pattern match
    `github.com/hyperscale-stack/*` (`GOINSECURE` and `GONOPROXY` do not
    affect checksum verification).

## Operator checklist

- [ ] Build with Go 1.27.3 or later, the latest patch release, and run
      `govulncheck` on your application.
- [ ] Pick a password hasher and review its cost against current hardware;
      raise its limits (`WithArgon2idLimits`, `WithBCryptMaxCost`) before
      importing hashes costlier than the defaults.
- [ ] HTTP Basic: build each `basic.Authenticator` once, configure its hasher
      with the parameters of the stored hashes (and implement
      `basic.PasswordRehasher`), bound the request time
      (`http.TimeoutHandler`), and limit failed attempts per account and
      per client (`basic.WithAttemptLimiter`).
- [ ] Behind a reverse proxy, store the client address it forwards
      (`security.WithClientAddr`, from the hop your proxy appended) before
      the transport adapters: attempt limits key on it.
- [ ] Rotate JWT signing keys; expose them through a JWKS endpoint
      (`oidc/provider` serves one).
- [ ] Keep the JWT allowlist asymmetric unless you truly need HMAC.
- [ ] Build JWT resource servers with `jwtsec.BearerVerifier` over a
      `NewVerifier(keys, WithIssuer(…), WithAudience(…),
      WithType(TypeAccessToken))`; fetch the authorization server's keys with
      `NewRemoteJWKS` and its default outbound policy, exempting only the
      subnet of an internal JWKS host (`WithOutboundPolicy`).
- [ ] Cap request headers at the transport (`http.Server.MaxHeaderBytes`,
      `grpc.MaxHeaderListSize`, about 64 KiB): bearer tokens are bounded by
      `jwtsec.DefaultMaxTokenSize` (16 KiB) by default.
- [ ] Use `Profile20BCP` or stricter; do not enable the `implicit` /
      `password` legacy grants without a documented reason.
- [ ] Give every confidential client that authenticates with a secret a
      high-entropy one. Register a client that cannot keep a secret as
      public (`none` + PKCE). Declare every client's `GrantTypeValues` and
      `ScopeValues` — an empty list allows nothing — and watch `OnError`
      for `ErrNoGrantTypesDeclared` / `ErrNoScopesDeclared` after an
      upgrade.
- [ ] When third parties register clients, set
      `AuthorizeConfig.TrustedRedirect`, so that errors before
      authentication never redirect to a client you do not trust.
- [ ] Validate every redirect URI at registration with
      `oauth2.ValidateRedirectURI`; register native apps with a reverse
      domain name scheme (`com.example.app:/cb`) or a loopback IP literal
      (`http://127.0.0.1/cb`).
- [ ] Protect the request carrying the consent decision against CSRF (a
      session-bound token, or `net/http.CrossOriginProtection`); replace
      the anti-framing headers of `/authorize` only for origins you trust.
- [ ] Register the resource servers calling `/introspect` as confidential
      clients, have them call it at the issuer of the tokens they accept,
      and set `ServerConfig.IntrospectionPolicy` when several resource
      servers or tenants share the authorization server.
- [ ] Rate-limit `/token`, `/revoke` and `/introspect` per `client_id` and
      per source address, and alert on the `invalid_client` failures
      `OnError` reports.
- [ ] Generate client secrets with at least 128 bits of entropy and keep
      only a hash of them, behind a `SecretMatcher` (`DefaultClient` holds
      them in cleartext).
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
- [ ] Bound refresh-token families with `grant.Config.RefreshFamilyTTL` —
      the longest session you accept, 30 days for instance — so a stolen
      refresh token kept alive by rotation dies with its family.
- [ ] Make the `IssuerResolver` return the same issuer for every endpoint
      of a realm (`/authorize`, `/token`, `/revoke`, `/introspect`), and
      authenticate users within `AuthorizeRequest.Issuer` in the
      `ConsentFunc`. With several issuers and one `ClientStore`, register
      every client at its issuers (`IssuerBoundClient`,
      `DefaultClient.IssuerValues`) or scope the store by issuer.
- [ ] With `store/sql`, apply the `ALTER TABLE` statements of each release
      (MIGRATION.md) before deploying it; keep PostgreSQL databases in
      `UTF8` and MySQL tables in `utf8mb4` with a strict `sql_mode` — a
      non-strict MySQL truncates an over-long value instead of refusing it.
- [ ] With `oidc/provider`: an https issuer the `IssuerResolver` never takes
      from an unvalidated `Host`; a `KeySource` backed by your key store,
      rotated through `KeyRing.Published` (publish, sign, retire once the ID
      Tokens it signed have expired); access-token audiences that are never
      relying parties' client IDs, and a `ClientStore` answering unknown IDs
      with `(nil, nil)` or `invalid_client`; `RefreshTokenScope =
      offline_access`; sessions scoped to their realm (and tenant), and
      clients to their issuers
      (`IssuerBoundClient`); CSRF tokens and anti-framing headers on the
      login and consent pages; `ErrUnknownSubject` from the `ClaimsSource`
      for disabled end-users, whose token families you also revoke; every
      application claim relying parties decide on declared in
      `Config.ClaimsSupported`, and the claim names end-users choose kept
      apart from them.
- [ ] Serve over HTTPS so `Secure` cookies and bearer tokens are protected.
- [ ] Generate session keys of 32 bytes or more from a cryptographic source
      and keep them in a secret store; keep the previous key after the new
      one while you rotate, so rotation does not sign everyone out; rotate
      the active key before it seals 2^32 cookies.
- [ ] Sessions: keep the default `__Host-session` cookie name; call
      `VerifyCSRF` on every state-changing request (sign-in form included)
      behind `net/http`'s `CrossOriginProtection`.
- [ ] SAML: import IdP metadata through a trusted channel, or fetch it from
      the IdP's https metadata URL with a `MetadataSource` pinned to its
      entity ID; never take a metadata URL from a request. Widen the
      outbound policy only for an on-premises IdP (`AllowedPrefixes`,
      `CheckURL`, `RootCAs`). Enable `InsecureAllowSHA1` only for an IdP
      that cannot do better, with a plan to remove it.
- [ ] SAML: share the transaction store and the replay cache between
      instances (`saml/sp/store/sql` or `saml/sp/store/redis`) and purge
      expired SQL rows. Give the SP least-privilege access to them: a Redis
      ACL limited to its key prefix, a database user limited to its two
      tables.
- [ ] SAML: load `samlsp.Config.TransactionKeys` from your secret store —
      the same keys on every instance, distinct from the OpenID Connect
      client's and the session keys — and rotate them by adding the new key
      last, then moving it first, then removing the old one after
      `TransactionTTL`; replace a leaked key at once.
- [ ] SAML: exempt the ACS routes from CSRF protection, start logins only
      from a same-origin gesture (a POST with a CSRF token, or
      `Sec-Fetch-Site` `same-origin` or `none`), rate-limit the login entry
      point and the ACS per client, serve the login on the ACS host, and
      key accounts on the connection and the persistent NameID — never on
      an email.
- [ ] SAML: let the ACS see the host the browser used: forward the
      original `Host` at the proxy, or pass `CompleteLogin` a copy of the
      request whose `Host` comes from your trusted proxy's header.
- [ ] SAML: set `Connection.ResponseOrigins` to the IdP page's origin when
      that page lets browsers send it (a Keycloak realm needs its
      Referrer-Policy header changed first); otherwise keep `TransactionTTL`
      short and never log full IdP redirect URLs.
- [ ] Install an OpenTelemetry `TracerProvider` to collect the spans.
- [ ] Give every route the attributes its voters check, and a voter for each
      attribute (an unsupported one denies); require a logged-in caller
      with `security.IsAuthenticated`, and store roles as `ROLE_<name>`
      and scopes as one `scope:<name>` authority each.
- [ ] Set the challenge scheme of each HTTP / ConnectRPC adapter to the
      scheme its extractors accept, with a printable-ASCII realm.
- [ ] On gRPC, install the authentication and authorization interceptors
      for both RPC kinds (`grpcsec.ServerOptions`,
      `grpcsec.AuthorizeServerOptions`).
- [ ] In your authenticators, wrap `security.ErrUnavailable` for a
      dependency that is temporarily down, a credential sentinel for a
      refusal — never a plain error.
- [ ] Keep the zero `outbound.Policy` in production; exempt only the exact
      subnets of on-premises identity providers in `AllowedPrefixes`, and
      restrict hosts and ports in `CheckURL` when tenants configure URLs.
- [ ] Give every OpenID Connect connection its own redirect URI
      (`/oidc/{connection}/callback`), registered exactly at its provider.
- [ ] Use a shared `TransactionStore` (`oidc/client/store/sql` or
      `store/redis`) when several instances serve callbacks, and schedule
      `PurgeExpired` with the SQL store.
- [ ] Load `oidcclient.Config.TransactionKeys` from your secret store — the
      same keys on every instance — and rotate them by adding the new key
      last, then moving it first, then removing the old one after
      `TransactionTTL`.
- [ ] Link accounts on (connection, issuer, subject), never on email;
      create a fresh session after each login.
- [ ] Start logins with a same-origin POST and rate limit them; exempt only
      the `form_post` callback routes from CSRF middleware.
- [ ] Rotate an OpenID Provider's keys on its relying parties' timetable:
      publish the next key at least an hour before it signs; after a leak,
      withdraw the key and ask relying parties to rebuild their clients
      (`oidc/client` keeps a withdrawn key for up to an hour).
- [ ] Prefer providers that send the RFC 9207 `iss` parameter; never
      register a connection's redirect URI at another provider.
- [ ] Serialize the refreshes of one grant across instances: providers
      that rotate refresh tokens with reuse detection revoke the grant
      when a rotated token is presented twice.
