# OpenID Connect client (`oidc/client`)

`github.com/hyperscale-stack/security/oidc/client` (package `oidcclient`) is
an OpenID Connect Relying Party: it logs users in through an OpenID Provider
with the Authorization Code flow and returns a verified identity — issuer,
subject and claims. It serves an identity broker federating enterprise
identity providers as well as an application logging in through such a
broker. It depends on the core and go-jose only — neither `oauth2` nor
`jwt`.

The library owns the protocol; the application owns everything around it:

| Library (this module)                                                           | Application                                                                     |
| ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| discovery, the authorization request (PKCE S256, state, nonce), the callback     | which connections exist, routing a login start to its connection               |
| browser binding, the transaction's integrity and single use                      | the transaction store's deployment (`TransactionStore`) and transaction keys   |
| the token request, ID Token validation (Core §3.1.3.7), UserInfo                 | account linking and provisioning, its own session, sign-out                    |
| the provider's JWK Set cache, outbound request policy                            | tenant isolation, rate limiting of login starts, what errors users see         |

`examples/oidc-client` is a complete, runnable demo: several connections
with their own callback routes, account linking on (connection, issuer,
subject), a local session. It runs against `examples/oidc-provider` out of
the box (`make e2e-oidc` drives both through a browser).

## Conformance status

No certification and no blanket conformance claim: this page lists what is
supported, how, and the tests that prove it;
[oidc-conformance.md](oidc-conformance.md) gathers the cross-cutting matrix,
the independent implementations it is checked against and the local runs of
the OpenID Foundation conformance suite. The client is checked in CI against
the provider of this repository (`internal/interop/oidcstack`, attacks and
failures included), against the independent example provider of
`github.com/zitadel/oidc/v3` and a pinned corpus of six real providers'
discovery documents (`internal/interop/oidcrp`).

Test names refer to `oidc/client` unless prefixed with `stack:`
(`internal/interop/oidcstack`) or `rp:` (`internal/interop/oidcrp`).

## Feature matrix

### Flows and requests

| Capability                          | Spec                                | Status                                                                                                                                                                  | Tests                                                                                                    |
| ----------------------------------- | ----------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| Authorization Code flow             | Core §3.1                           | Supported; `openid` always requested                                                                                                                                    | `TestBeginParameters`, `TestEndToEndQuery`, stack: `TestCodeFlowAgainstOurProvider`, rp: `TestZitadelCodeFlow` |
| PKCE                                | RFC 7636                            | Always S256, the verifier derived from the browser binding; a public client requires the provider to advertise S256                                                    | `TestBeginChallengeMatchesVerifier`, `TestCapabilities`, stack: `TestCodeInjectionIsDefeated`, `TestPKCEDowngradeIsRefused` |
| `state`, `nonce`                    | RFC 6749 §10.12, Core §3.1.2.1, §15.5.2 | Always sent, bound to the user agent through the binding secret; the transaction is consumed once                                                                  | `TestCompleteBinding`, `TestCompleteReplay`, `TestIDTokenNonce`, stack: `TestCallbackReplay`             |
| Response modes                      | OAuth 2.0 Form Post Response Mode   | `query` and `form_post` (refused at `New` when the provider lists its response modes without it); `fragment` and JARM refused                                                        | `TestCompleteQuery`, `TestCompleteFormPost`, stack: `TestFormPostRefusedAgainstAQueryOnlyProvider`      |
| `prompt`, `max_age`, hints          | Core §3.1.2.1                       | Sent as given; `auth_time` required and checked against `max_age`                                                                                                       | `TestBeginHints`, `TestIDTokenAuthTime`, stack: `TestReauthenticationThroughTheClient`, `TestHintsReachTheProvider` |
| No parameter twice                  | RFC 6749 §3.1                       | The authorization endpoint's query is kept; `ExtraParams` may not repeat a parameter the client sends, one of that query or each other — names compared case-insensitively, `.` read as `_` (servers such as ASP.NET and PHP read them so); `New` refuses an endpoint query that does | `TestBeginSendsEveryParameterOnce`, `TestBeginRefusesOtherSpellingsOfReservedParams`, `TestBeginRefusesParamsOfTheEndpointQuery`, `TestEndpointURLs` |
| `acr_values`                        | Core §3.1.2.1, §2                   | Sent as given; the ID Token's `acr` must then be one of them (a provider ignoring them fails the login)                                                                 | `TestIDTokenACR`, stack: `TestACRValuesThroughTheClient`, rp: `TestZitadelACRValues`                     |
| Authorization errors                | RFC 6749 §4.1.2.1, Core §3.1.2.6    | `AuthorizationError` with the provider's code; nothing redeemed                                                                                                         | `TestCompleteAuthorizationError`, stack: `TestPromptNoneThroughTheClient`, `TestConsentDeniedThroughTheClient` |
| RFC 9207 `iss`                      | RFC 9207                            | Compared when present; required when the provider advertises it                                                                                                        | `TestCompleteIssParameter`, stack: `TestMixUpBetweenIssuersOfOneProvider`                                |
| Mix-up defense                      | RFC 9700 §4.4                       | The response must arrive on the connection's own redirect URI, for a transaction of that connection, issuer, client, redirect URI and response mode                      | `TestCompleteMixUp`, `TestCompleteTransactionMismatch`, stack: `TestMixUpWithAnAttackerProvider`, `TestMixUpResidualWithoutRFC9207` |
| Implicit and hybrid flows, PAR, request objects, `claims` parameter | Core §3.2, §3.3, §6, §5.5; RFC 9126 | Not supported                                                                                                       | —                                                                                                        |

### Tokens and claims

| Capability                       | Spec                                     | Status                                                                                                                                                       | Tests                                                                                                       |
| -------------------------------- | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------- |
| Client authentication            | Core §9, RFC 6749 §2.3.1                 | `client_secret_basic` (form-urlencoded first), `client_secret_post`, `none`; `private_key_jwt`, `client_secret_jwt`, mTLS not supported                      | `TestTokenClientAuthentication`, stack: `TestCodeFlowAgainstOurProvider`                                     |
| Token response                   | RFC 6749 §5.1, Core §3.1.3.3             | Parsed strictly; error bodies of 400 and 401 answers become `TokenError`; redirects never followed                                                           | `TestTokenResponse`, `TestTokenRedirectNotFollowed`, stack: `TestTokenResponseSubstitution`                  |
| ID Token validation              | Core §3.1.3.7, RFC 8725                  | Signature, `iss`, `sub`, `aud` (further audiences only when trusted), `azp`, `exp`, `iat`, `nbf`, `nonce`, `auth_time`, `acr`, `at_hash` when present, `typ` absent or `JWT`; before go-jose parses it, the JOSE header is strict JSON of at most 4 KiB without `jwk`, `x5c`, `jku` or `x5u` (Core §2) | `TestIDTokenKeyBearingHeaders`, `TestIDTokenHeaderStrict`, `TestCheckRawHeaderRefusesBeforeParsing`, `TestIDTokenIssuerAndSubject`, `TestIDTokenAudience`, `TestIDTokenTimes`, `TestIDTokenAccessTokenHash`, `TestIDTokenHeader`, stack: `TestResignedIDTokensAreRefused` |
| Signing algorithms               | Core §15.1, RFC 8725 §3.1                | RS256/384/512, PS256/384/512, ES256/384/512, EdDSA (Ed25519); HMAC and `none` refused                                                                       | `TestIDTokenAlgorithms`, stack: `TestCodeFlowSigningAlgorithms`                                             |
| Token confusion                  | RFC 9068 §5, RFC 8725 §3.11              | An `at+jwt` access token is never accepted as an ID Token                                                                                                     | `TestAccessTokenNotAcceptedAsIDToken`, stack: `TestIDTokenUsedAsAnotherToken`                               |
| Encrypted ID Tokens              | Core §10.2                               | Not supported, refused                                                                                                                                        | `TestIDTokenSerialization`                                                                                  |
| UserInfo                         | Core §5.3, RFC 6750 §2.1                 | Bearer token in the `Authorization` header, to the connection's endpoint only; `sub` must equal the ID Token's                                               | `TestUserInfo`, `TestUserInfoRefusesForeignIdentity`, stack: `TestUserInfoSubstitution`                      |
| Signed or encrypted UserInfo     | Core §5.3.2                              | Not supported, refused (`ErrUserInfoUnsupported`)                                                                                                            | `TestUserInfoResponses`                                                                                     |
| Aggregated and distributed claims | Core §5.6.2                             | Returned as received, never resolved                                                                                                                          | —                                                                                                           |
| Refresh                          | RFC 6749 §6, Core §12                    | Refresh tokens are returned; the application redeems them and validates refreshed ID Tokens itself                                                            | stack: `TestRefreshOfAClientLogin`                                                                          |

### Discovery, keys and deployment

| Capability                   | Spec                       | Status                                                                                                                                                       | Tests                                                                                                 |
| ---------------------------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------- |
| Discovery                    | Discovery §4               | Required; the metadata issuer must equal the configured one byte for byte; templated multi-tenant issuers refused; WebFinger and static metadata not supported | `TestDiscoveryURL`, `TestIssuerMismatch`, `TestRequiredMetadata`, `TestStrictMetadataJSON`, rp: `TestProviderMetadataCorpus` |
| JWK Set                      | Core §10.1.1, RFC 7517     | Cached one hour; an unknown `kid` refetches at most every 10 s; stale keys serve at most 24 h while the endpoint fails; never refetched on a bad signature | `TestKeySetTTL`, `TestUnknownKidIsRateLimited`, `TestKeySetStaleOnFailure`, `TestNoRefetchOnBadSignature`, stack: `TestDocumentedRotationIsInvisibleToTheClient`, `TestKeyWithdrawalWindow` |
| Outbound requests            | Discovery §4.1, §7.2       | Through `outbound`: https, public destinations, bounded time and size; no redirects for token and UserInfo; discovery and JWK Set redirects only with `MaxRedirects`, and never to another origin than the one requested | `TestDiscoveryHTTP`, `TestUserInfoTransport`, `TestDiscoveryRedirectStaysOnTheIssuerOrigin`, `TestKeySetRedirectStaysOnTheJWKSOrigin` |
| Transaction stores           | —                          | `storage/memory`, `store/sql`, `store/redis`; atomic single consumption; integrity keyed by `Config.TransactionKeys`                                         | `TestMemoryStoreConformance`, `TestStoreWriterCannotForgeIntegrity`, `TestTransactionKeyRotation`, stack: `TestConcurrentCallbacksAcrossReplicas`, `TestRealBackendCallbackRace` |
| Failures                     | RFC 9700 §4.5.3.2          | Fail closed: no identity, no token of a failed login                                                                                                         | stack: `TestProviderStorageFailuresReachTheClient`, `TestTokenResponseLostAfterCommit`, `TestJWKSOutage`, `TestDiscoveryOutage` |
| Logout, dynamic registration | Session/Front/Back-Channel/RP-Initiated Logout, Registration | Not supported                                                                                                                  | —                                                                                                     |

## Integration guide

### Wiring

```go
client, err := oidcclient.New(ctx, oidcclient.Config{
	ConnectionID:    "acme",
	Issuer:          "https://login.acme.example",
	ClientID:        "my-client",
	ClientSecret:    oidcclient.NewSecret(secret),
	AuthMethod:      oidcclient.AuthMethodClientSecretBasic,
	RedirectURL:     "https://app.example/oidc/acme/callback",
	Scopes:          []string{"profile", "email"},
	Store:           store, // sqlstore or redisstore with several instances
	// 32+ secret bytes, shared by every instance
	TransactionKeys: []oidcclient.Secret{oidcclient.NewSecret(string(key))},
})

mux.HandleFunc("POST /login/acme", func(w http.ResponseWriter, r *http.Request) {
	_ = client.StartLogin(w, r, oidcclient.AuthOptions{})
})
mux.HandleFunc("GET /oidc/acme/callback", func(w http.ResponseWriter, r *http.Request) {
	id, err := client.HandleCallback(w, r)
	// on success: a fresh local session for (connection, issuer, subject),
	// then 303 to a clean URL
})
```

- One `Client` per connection — provider, client registration and redirect
  URI. `New` discovers the provider; build connections at startup or cache
  them: discovery is a network round trip.
- Start logins on a user action from the application's own origin (a POST
  behind `http.CrossOriginProtection` or a CSRF token) and rate limit them:
  each start writes a transaction, and non-browser clients pass
  `CrossOriginProtection`. With `storage/memory`, bound what a flood can
  hold with `memory.WithCapacity(n)` (a full store answers `memory.ErrFull`;
  `examples/oidc-client` maps it to 503 and rate-limits starts per client
  and per network — an IPv4 /24, an IPv6 /48 — so that one network cannot
  fill it). The capacity bounds memory, not availability: a flood from
  enough networks fills the store and new logins fail until transactions
  expire, so rate-limit at the edge too.
- `Config.Outbound` is the request policy: the default reaches public https
  destinations only and follows no redirect. Exempt an on-premises
  provider's network with `AllowedPrefixes`; `AllowHTTP` is for local
  development only (`examples/oidc-client`'s `OIDC_DEV_ALLOW_LOOPBACK`
  limits it to the loopback interface). `MaxRedirects` lets the discovery
  and JWK Set requests follow redirects within the origin they were sent
  to — the issuer's, the `jwks_uri`'s — never to another one; token and
  UserInfo requests never follow any.

### Connections and redirect URIs

Give every connection its own redirect URI, distinct from every other
connection's — this is the mix-up defense (RFC 9700 §4.4.2): `Complete`
refuses a response received on another URL, or carrying a transaction of
another connection, issuer or client (`ErrTransactionMismatch`). Never route
callbacks by the state value. A provider advertising RFC 9207 is
additionally checked on `iss` (`ErrIssuerParameter`). One gap remains, the
one RFC 9700 §4.4.2.2 names: when the honest provider does not send `iss`
and an attacker registered, at that provider, a client whose redirect URI is
the attacker connection's callback, nothing tells the responses apart —
`stack: TestMixUpResidualWithoutRFC9207` shows the honest code reaching the
attacker's token endpoint. Prefer providers that support RFC 9207, never
register a connection's redirect URI at another provider, and on a
multi-tenant provider use the tenant's own issuer (one registration valid
at several issuers defeats the distinct redirect URIs).

### Callback and session

- In `form_post` mode exempt the callback route from CSRF middleware: the
  cross-site POST is the protocol, the binding cookie its defense. Leave
  the body unread before `HandleCallback`, or let it reuse `r.PostForm`.
- Behind a reverse proxy, preserve the Host header (`HandleCallback`
  compares the URL the browser used) or call `Complete` with the public URL.
- After a successful callback, create a fresh session (a new ID) and
  answer 303 to a clean URL, so the code leaves the browser history.
- Every credential — client secret, transaction keys, binding secret,
  tokens — is an `oidcclient.Secret`: it prints, logs and encodes as
  `REDACTED` wherever it sits (`TestSecretsNeverPrint`), and `Reveal()`
  returns it where it is used. An application persisting tokens reveals
  them explicitly: `Identity` and `Tokens` encode them `REDACTED`.
- Show users a generic message on failure: `AuthorizationError` and
  `TokenError` carry the provider's untrusted text, and errors of `New` may
  name an allowed destination's address. Provider-controlled text an error
  echoes — an issuer, a media type, a redirect target, a JOSE header
  member, an HTTP/2 GOAWAY's debug data — is quoted and cut to about 256
  bytes, so it cannot flood a log.

### Several instances

Pending logins live in the `TransactionStore` between `Begin` and
`Complete`. With several instances, use `oidc/client/store/sql`
(PostgreSQL, MySQL, SQLite; run `PurgeExpired` periodically) or
`oidc/client/store/redis`: consumption is atomic across instances
(`stack: TestRealBackendCallbackRace` races one callback over two replicas
on real servers). Every instance serving callbacks needs the same
`Config.TransactionKeys` — 32 bytes or more from a cryptographic source,
kept like a session key. Rotate them in three steps: add the new key last
everywhere, move it first, remove the old one once `TransactionTTL` has
elapsed. The store is trusted for availability and single consumption only:
a transaction altered in it fails its login (`ErrTransactionIntegrity`).

### Provider keys and rotation

The client caches the provider's JWK Set for one hour, refetches it at most
every 10 seconds when an ID Token names an unknown `kid`, and keeps using the
cached keys for at most 24 hours while the JWK Set endpoint fails. What it
means for the provider's operators:

| Event                                   | Effect on this client                                                                                          |
| --------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| A key is published before it signs      | Learned at the next refresh (at most one hour), or at the first ID Token naming it — rotation is invisible      |
| A key signs right after being published | Logins within 10 s of the previous refetch fail closed (`ErrUnknownSigningKey`), the next ones succeed          |
| A key is withdrawn (leaked)             | ID Tokens it signs keep verifying until the cached set is an hour old; rebuild the `Client` to drop it at once |
| The JWK Set endpoint is down            | Cached keys keep verifying for up to 24 hours; a key the cache lacks cannot be learned                          |

`stack: TestDocumentedRotationIsInvisibleToTheClient`,
`TestAbruptRotationWithinTheRefreshInterval` and `TestKeyWithdrawalWindow`
pin this timetable. Other relying parties differ (go-oidc refetches on any
unknown `kid`; generic HTTP caches honor the JWK Set's `Cache-Control`);
[oidc-provider.md](oidc-provider.md) gives the provider's side.

### Identities and account linking

The verified identity is the issuer and subject pair (Core §5.7): link
accounts on (connection, issuer, subject), never on email, phone or
username. Read the validated values from the `Identity` fields and decode
other claims with `Identity.DecodeClaims` (`UserInfo.Decode` for UserInfo)
or into a map, never with `encoding/json` into a struct: it matches names
case-insensitively, so a lone `EMAIL_VERIFIED` — another claim, which a
provider letting users name attributes may release — would read as
`email_verified` (`TestLoneCaseVariantClaimIsIgnored`).

To link an identity to an account already signed in, start the
login with a CSRF-protected POST after a recent re-authentication, put a
random value bound to the local session in `AuthOptions.AppState`, and link
only when `Identity.AppState` matches it.

### Refresh tokens

The client returns the provider's refresh token and has no refresh helper:
the application redeems it (RFC 6749 §6) and validates any refreshed ID
Token itself (Core §12.2: signature, then the same `iss`, `sub`, `aud` and
`auth_time` as the original, a new `iat`, no `nonce`). Providers that rotate refresh tokens with reuse detection —
this repository's does — revoke the whole grant when a rotated token is
presented again (`stack: TestRefreshReuseRevokesTheClientsTokens`):
serialize the refreshes of one grant across the application's instances.

### What the library does not do

Sign-out (no logout specification is supported), dynamic client
registration, WebFinger, the `claims` parameter, request objects, PAR,
JARM, DPoP, encrypted ID Tokens, signed or encrypted UserInfo, aggregated
and distributed claims resolution, refresh — and everything the table at
the top assigns to the application. See
[security-considerations.md](security-considerations.md#openid-connect-client)
for the threat model and [LIMITATIONS.md](../LIMITATIONS.md) for the
known gaps.
