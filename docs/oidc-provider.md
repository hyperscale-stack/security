# OpenID Provider (`oidc/provider`)

`github.com/hyperscale-stack/security/oidc/provider` (package `oidcprovider`)
turns the `oauth2` authorization server into an OpenID Provider — OpenID
Connect Core 1.0 incorporating errata set 2 and OpenID Connect Discovery 1.0
— through the `oauth2.Extension` hooks: one `/token` endpoint, ID Tokens
minted next to the access token, the authentication event recorded with the
grant and carried by every refresh. It depends on `oauth2`, `jwt` and the
core only.

The provider owns the protocol; the application owns the end-user:

| Provider (this module)                                                                 | Application                                                                 |
| -------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| validates authentication requests (prompt, max_age, nonce, claims, id_token_hint, …)    | end-user sessions, login and consent pages, consent records (`Interaction`) |
| re-checks every approval against the request (freshness, realm, subject, acr, consent) | end-user claims (`ClaimsSource`)                                            |
| issues and signs ID Tokens at the code exchange and at every refresh                  | signing keys and their rotation (`KeySource`)                               |
| serves UserInfo, Discovery and the JWK Set                                             | issuers (`oauth2.IssuerResolver`), static clients (`oauth2.ClientStore`)    |

`examples/oidc-provider` is a complete, runnable demo: login and consent
pages with CSRF tokens, sessions, `prompt` handling, offline access. It
runs together with the relying party of `examples/oidc-client` (see its
package documentation), which is how the opt-in end-to-end suite
`e2e/oidc` (`make e2e-oidc`) drives both, through a browser too.

## Conformance status

No certification and no blanket conformance claim: this page lists, row by
row, what is supported, how, and the tests that prove it. The OpenID
Foundation conformance suite's OP plans run locally against the provider
(`make conformance`) — not a certification either: configuration, results
and gaps are in [oidc-conformance.md](oidc-conformance.md), with the
cross-cutting matrix. Interoperability is checked in CI against an
independent relying party — `github.com/coreos/go-oidc/v3` v3.21.0 and
`golang.org/x/oauth2` v0.37.0, in the test-only module
`internal/interop/oidcop` (never a dependency of a production module) — and
against this repository's relying party, attacks included
(`internal/interop/oidcstack`).

Test names refer to `oidc/provider` unless prefixed with `interop:`
(`internal/interop/oidcop`), `stack:` (`internal/interop/oidcstack`),
`oauth2:` or `jwt:`.

## Feature matrix

### Flows and requests

| Capability                                  | Spec                               | Status                                                                                                                                                                                                                               | Tests                                                                                                                   |
| ------------------------------------------- | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------- |
| Authorization Code flow                     | Core §3.1                          | Supported                                                                                                                                                                                                                            | `TestIDTokenClaims`, interop: `TestInteropCodeFlowS256`, `TestInteropCodeReplay` |
| PKCE                                        | RFC 7636                           | As the core's `Profile` decides: `S256` required under `Profile20BCP` (default) and `Profile21Draft`; optional under `Profile20`, which also allows `plain`                                                                          | `TestDiscoveryPKCEMethodsFollowTheProfile`, interop: `TestInteropPublicClient`                                          |
| Plain OAuth 2.0 requests (no `openid`)      | Core §3.1.2.1                      | OAuth 2.0 semantics: no ID Token, no UserInfo; the realm rule and the `offline_access` rule only | `TestPlainOAuth2RequestKeepsOAuth2Semantics`, `TestPlainOAuth2CodeExchange`, `TestRefreshOfAPlainOAuth2Grant`, `TestPlainOAuth2OfflineAccessNeedsTheDecision` |
| Implicit and hybrid flows                   | Core §3.2, §3.3                    | Not supported, not advertised: an OpenID request with another `response_type` gets `unsupported_response_type`                                                                                                                      | `TestOpenIDImplicitRefused`                                                                                             |
| Response modes                              | Core §3.1.2.1; OAuth 2.0 Multiple Response Types | `query` only (advertised); the core refuses any other with a bare `400`, never redirected                                                                                                                              | `TestDiscoveryDocument`, oauth2: `TestAuthorizeRefusesUnsupportedResponseModes`                                                                   |
| `redirect_uri`                              | Core §3.1.2.1                      | REQUIRED for OpenID requests: missing → `400`, never redirected — once the core accepted the request: the core's state, response type, scope, PKCE and nonce checks run first and redirect their errors to the client's sole registered redirect URI (OAuth 2.0 behaviour) | `TestOpenIDRequestWithoutRedirectURIIsNotRedirected` |
| Repeated parameters                         | RFC 6749 §3.1                      | Refused: `client_id`, `redirect_uri`, `response_mode` → `400`, never redirected — by the oauth2 core itself, before any other check; any other → `invalid_request` (the core's parameters by the core, the OpenID ones by the provider). An empty value is no occurrence, wherever it stands: it is omitted, by the provider as by the core | `TestDuplicatedParameters` |
| `nonce`                                     | Core §3.1.2.1, §2                  | Optional (code flow); at most 512 bytes of UTF-8 without NUL, else `invalid_request` — the oauth2 core enforces the same bound on every request, OpenID or not; in the ID Token of the code exchange only | `TestNonceBounds`, `TestIDTokenClaims`, `TestIDTokenWithoutNonceHasNoNonce`                                             |
| `prompt`                                    | Core §3.1.2.1                      | `none`, `login`, `consent`, `select_account` reach the `Interaction`; unknown values ignored; `none` with another value → `invalid_request`; read whole (never truncated), without allocating per separator | `TestPromptParsing`, `TestPromptIsReadWhole` |
| `prompt=none`                               | Core §3.1.2.1, §3.1.2.6            | `Interaction.AuthorizeSilently` only — it has no `ResponseWriter`; its refusals (`login_required`, `consent_required`, `interaction_required`, `account_selection_required`) are redirected — to a client `oauth2.AuthorizeConfig.TrustedRedirect` trusts: for an untrusted one they are a bare 400, never redirected (RFC 9700 §4.11.2). The provider's own refusals carry fixed descriptions: no session, a session of another realm, of another end-user or a stale one read the same on the wire (the reason goes to the `ErrorHook`) | `TestPromptNoneIsSilent`, `TestPromptNoneRefusals`, `TestSilentRefusalsRevealNothing`, `TestPromptNoneWithoutDecisionIsAServerError`, interop: `TestInteropPromptNone` |
| `prompt=login`                              | Core §3.1.2.1                      | Enforced by the provider: an authentication older than the request (to the second of `auth_time`) → `login_required`                                                                                                              | `TestFreshnessIsEnforcedByTheProvider`, `TestRequestCheck`, interop: `TestInteropReauthentication` |
| `max_age`                                   | Core §3.1.2.1, §2                  | Enforced (`auth_time + max_age` ≥ request time, to the second); `1*DIGIT`, longer values clamped to 2³¹−1 s, anything else → `invalid_request`; `auth_time` always in the ID Token                                                | `TestMaxAgeParsing`, `TestFreshnessIsEnforcedByTheProvider`, `TestIDTokenCarriesTheAuthenticationEvent`, interop: `TestInteropReauthentication` |
| `id_token_hint`                             | Core §3.1.2.1, §3.1.2.2            | Verified: signed by a key the issuer publishes, `iss` the issuer, the client among its audiences, a `sub`, typed `JWT` or untyped (an `at+jwt` is refused); its expiry is not checked. It designates the end-user (another one → `login_required`). Invalid → `invalid_request` | `TestIDTokenHint`, `TestIDTokenHintOfARetiredKey`, `TestIDTokenHintDesignatesTheEndUser`, interop: `TestInteropIDTokenHint` |
| `login_hint`, `display`, `ui_locales`, `claims_locales`, `acr_values` | Core §3.1.2.1, §5.2, §15.1 | Passed to the `Interaction`, bounded; never fail a request; `acr_values` is voluntary. `ui_locales`, `claims_locales`, `acr_values`: the first 32 values of at most 2048 bytes of UTF-8 — a longer value is ignored; `login_hint` at most 1024 bytes, `display` 255. `claims_locales` reaches the `Interaction` only, not the `ClaimsSource` (Core §15.1's minimum) | `TestPassthroughParameters`, `TestOversizedListParametersAreIgnored`, `TestVoluntaryACRIsNotEnforced` |
| `claims` parameter                          | Core §5.5, §5.5.1                  | Supported (advertised): strict JSON, bounded; a requested claim is released only when the end-user agrees (`Decision.Claims`) and its value matches a `value`/`values` constraint; protocol claims, their case variants and other spellings of known claims are never shown nor released (see [Claims](#claims)) | `TestClaimsParameterParsing`, `TestClaimsParameterRefusals`, `TestReleasedClaims`, `TestValueConstraintsMatchScalarsOnly`, `TestTheInteractionIsShownReleasableClaimRequestsOnly`, interop: `TestInteropClaimsParameter` |
| Essential `acr`                             | Core §5.5.1.1                      | Enforced: unmet → `access_denied`, `login_required` under `prompt=none`; an authentication without acr never meets it. `acr` and `sub` values must be non-empty strings (`null` or `""` → `invalid_request`). Without `value`/`values`, an essential acr is not enforced (Core §5.5.1). The values of a voluntary `acr` request join `Request.ACRValues`, after those of `acr_values`, once each | `TestEssentialACRIsEnforced`, `TestRequestCheck`, `TestClaimsParameterRefusals`, `TestVoluntaryACRRequestsReachTheInteraction` |
| `sub` claim request                         | Core §5.5.1                        | Designates the end-user, like a hint; conflicting designations → `invalid_request`                                                                                                                                                  | `TestClaimsParameterDerivedRequirements`, `TestIDTokenHintDesignatesTheEndUser`                                         |
| `request`, `request_uri`                    | Core §6                            | Not supported: `request_not_supported`, `request_uri_not_supported`; advertised as unsupported                                                                                                                                      | `TestRequestObjectParametersRefused`, `TestDiscoveryDocument`                                                           |
| `registration` parameter                    | Core §7.2.1                        | Not supported: `registration_not_supported`                                                                                                                                                                                          | `TestRequestObjectParametersRefused`                                                                                    |
| Realm of the authentication                 | Core §16.15                        | `AuthenticationEvent.Issuer` must be the request's issuer: else `login_required` (OpenID) or `access_denied` (OAuth 2.0)                                                                                                            | `TestRealmIsEnforced`, `TestRequestCheck`, stack: `TestRefusalsRevealNoSession` |
| Consent                                     | Core §3.1.2.4                      | `Decision`: approval, `Scope` narrowing (keeps `openid`), `Claims`, `Refusal`; an empty decision → `access_denied`                                                                                                                 | `TestDecisionScopeNarrows`, `TestInteractionFailures`, `TestApprovalContractViolations`, interop: `TestInteropConsentNarrowsScope` |
| `offline_access`                            | Core §11                           | Every request: kept only when `Decision.OfflineAccess` grants it — the consent dialog (`OfflineAccessPrompted`: `prompt=consent` required for an OpenID request, `prompt` being no OAuth 2.0 parameter) or the application's policy (`OfflineAccessByPolicy`) — else dropped from the grant — and always outside the code flow (Core §11: an implicit request keeps no `offline_access`); an approval left without any scope → `access_denied`. OpenID grants: a refresh token without that consent fails closed (`server_error` at issuance, `invalid_grant` at refresh) unless `Config.AllowRefreshWithoutOfflineAccess`. Plain OAuth 2.0 grants carry no context: only their scope is gated, their refresh tokens follow `grant.Config.RefreshTokenScope` | `TestOfflineAccessRequiresConsent`, `TestPlainOAuth2OfflineAccessNeedsTheDecision`, `TestRequestReportsOfflineAccessForEveryRequest`, `TestRefreshWithoutOfflineConsentFailsClosed`, interop: `TestInteropRefresh` |

### ID Tokens and refresh

| Capability                       | Spec                                 | Status                                                                                                                                                                                       | Tests                                                                                               |
| -------------------------------- | ------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| ID Token claims                  | Core §2, §3.1.3.6                    | `iss`, `sub`, `aud` (the client ID, a string), `exp`, `iat`, `auth_time` (always), `nonce` (code exchange), `acr` and `amr` (from the event), `at_hash`; no `azp` (one audience)              | `TestIDTokenClaims`, `TestIDTokenCarriesTheAuthenticationEvent`                                     |
| Signing algorithms               | Core §15.1, §16.14; Registration §2  | RS256 (mandatory, default), RS384/512, PS256/384/512, ES256/384/512 per client (`IDTokenSigningClient`); never `none`, HS* or EdDSA. No key for the client's algorithm → `server_error` before any interaction | `TestIDTokenSigningAlgorithms`, `TestClientWithoutAnAlgorithmGetsRS256`, `TestClientAlgorithmWithoutAKey`, interop: `TestInteropSigningAlgorithms` |
| Application claims               | Core §5.4, §5.5                      | Only the claims requested through `claims` and released; protocol claims never come from the source, nor their case variants; other spellings of known claims, case variants of one another, invalid names, malformed values, null and empty strings dropped (see [Claims](#claims)). Scope claims (`profile`, `email`, …) go to UserInfo only | `TestIDTokenClaimsFromTheClaimsParameter`, `TestValueConstraintsMatchScalarsOnly`, `TestProtocolClaimsCannotBeAliasedByCaseVariants`, `TestKnownClaimsAreReleasedUnderTheirExactSpellingOnly`, `TestClaimNamesCollidingUnderCaseFoldingAreDropped`, `TestReleasedClaimNamesAreValidAndUnique`, `TestReleasedClaimValuesAreWellFormed`, interop: `TestInteropCaseVariantClaimsNeverReachTheRP` |
| Code issued for OpenID           | Core §3.1.3.2                        | An `openid` code without the provider's context → `invalid_grant`                                                                                                                            | `TestOpenIDCodeWithoutContextIsRefused`                                                             |
| Account validity                 | —                                    | `ClaimsSource` queried on every exchange of an OpenID grant: `ErrUnknownSubject` → `invalid_grant`                                                                                          | `TestCodeExchangeFailures`, `TestRefreshChecksTheAccountEvenWithoutOpenID`                          |
| Token confusion                  | RFC 9068 §5, RFC 8725 §3.12          | An access-token audience equal to the requesting client's ID → `server_error` (another client's ID is not compared: audiences are never client IDs); JWT access tokens are typed `at+jwt` | `TestCodeExchangeFailures`, jwt: `TestOAuth2AccessTokenSignerFollowsRFC9068`, interop: `TestInteropJWTAccessTokenIsNotAnIDToken`, stack: `TestIDTokenUsedAsAnotherToken` |
| Refresh                          | Core §12.2                           | An ID Token at every refresh of an OpenID grant: same `iss`, `sub`, `aud`; new `iat`; the original `auth_time`, `acr`, `amr`; no `nonce`; none once the scope drops `openid`                | `TestRefreshIDTokensFollowCore12_2`, `TestRefreshWithoutOpenIDHasNoIDToken`, interop: `TestInteropRefresh`, `TestInteropRefreshReuse` |
| Encrypted ID Tokens              | Core §10.2                           | Not supported, not advertised                                                                                                                                                                | —                                                                                                   |

### UserInfo

| Capability                       | Spec                              | Status                                                                                                                                                                                                | Tests                                                                                     |
| -------------------------------- | --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Transport                        | Core §5.3.1; RFC 6750 §2          | GET and POST; bearer token in the `Authorization` header or a form-encoded POST body; a URI query token is not supported (ignored alone, a second method otherwise)                                  | `TestUserInfoMethods`, `TestUserInfoTokenMethods`                                         |
| Token validation                 | Core §5.3; RFC 6750 §3.1          | b64token syntax, known and outside a revoked family, unexpired, issued under the request's issuer to an OpenID grant of a client still registered at that issuer, scope holding `openid` | `TestUserInfoErrors`, `TestUserInfoRefusesUnusableRecords`, `TestUserInfoRefusesTokensOfClientsNotAtTheIssuer` |
| Errors                           | RFC 6750 §3, §3.1; Core §5.3.3    | `WWW-Authenticate: Bearer realm="<issuer>"`: no error information without a token, `invalid_request` (400), `invalid_token` (401), `insufficient_scope` (403, `scope="openid"`); server failures 500 | `TestUserInfoErrors`, `TestUserInfoTokenMethods`, `TestUserInfoErrorsReachTheHook`        |
| Claims                           | Core §5.3.2, §5.4, §5.5           | The access token's scope claims and the released `userinfo` claim requests, under the rules of the ID Token's (see [Claims](#claims)); `sub` is the token's — the ID Token's, never a case variant from the source; JSON, `Cache-Control: no-store` | `TestUserInfoScopeClaims`, `TestUserInfoClaimsParameter`, `TestUserInfoSubMatchesIDToken`, `TestUserInfoHeaders`, `TestProtocolClaimsCannotBeAliasedByCaseVariants` |
| CORS                             | Core §5.3                         | Not built in (a SHOULD): the application's middleware                                                                                                                                                  | —                                                                                         |
| Signed or encrypted UserInfo     | Core §5.3.2                       | Not supported, not advertised                                                                                                                                                                          | —                                                                                         |
| Aggregated and distributed claims | Core §5.6.2                      | Not supported                                                                                                                                                                                          | —                                                                                         |

### Discovery, keys, issuers and clients

| Capability                       | Spec                                   | Status                                                                                                                                                                                         | Tests                                                                                                                   |
| -------------------------------- | -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| Discovery                        | Discovery §3, §4                       | Per-request issuer, path issuers (§4.1); advertises only what is served; consistent with the RFC 8414 metadata                                                                                | `TestDiscoveryDocument`, `TestDiscoveryPathIssuers`, `TestPathIssuersUseTheirOwnKeyRings`, `TestDiscoveryConsistentWithRFC8414Metadata`, interop: `TestInteropDiscoveryMetadata`, `TestAdvertisedURLsAreServed` |
| Mix-up defense                   | RFC 9207                               | Every authorization response carries `iss`, the issuer as the `IssuerResolver` returns it; advertised. Except the `server_error` of a failed `IssuerResolver`, redirected without `iss` — a deliberate deviation from RFC 9207 §2 (the code review preferred a bare 500; see [security-considerations.md](security-considerations.md)) | oauth2: `TestAuthorizationResponsesNameTheIssuer`, interop: `TestInteropCodeFlowS256`, stack: `TestMixUpBetweenIssuersOfOneProvider` |
| JWK Set                          | RFC 7517; Core §10.1.1                 | Public signature keys only, per issuer; rotation through `KeyRing.Published`                                                                                                                  | `TestJWKSPublishesPublicKeysOnly`, `TestJWKSIsPerIssuer`, `TestPathIssuersUseTheirOwnKeyRings`, `TestKeyRotationThroughJWKS`, interop: `TestInteropKeyRotation` |
| Key rings                        | RFC 7518 §3; RFC 8725 §3.1             | RS256 key required; one key per algorithm and one algorithm per key; RSA ≥ 2048 bits, curves bound to algorithms, unique `kid`s; no private or symmetric key published; validated on every use | `TestKeyRingValidate`, `TestJWKSFailsClosed`, stack: `TestDocumentedRotationIsInvisibleToTheClient` |
| Issuer identifier                | Core §2, §16.15; Discovery §3, §4.3    | An `https` URL with a host, without user info, query or fragment, in canonical form; `http` only for an exact loopback host with `Config.AllowInsecureLoopbackIssuer`                         | `TestIssuerValidation`, `TestIDTokenIssuerIsCheckedAtTheExchange`                                                       |
| Subject types                    | Core §8                                | `public` only; pairwise not supported                                                                                                                                                         | `TestDiscoveryDocument`                                                                                                 |
| Client authentication            | Core §9; RFC 6749 §2.3.1               | `client_secret_basic` (form-encoded credentials), `client_secret_post`, `none`; `client_secret_jwt`, `private_key_jwt` and mTLS not supported                                                | oauth2: `TestBasicDecodesFormURLEncodedCredentials`, interop: `TestInteropCodeFlowS256`, `TestInteropClientSecretPost`  |
| Client registration              | Registration                           | Static clients (`oauth2.ClientStore`); no dynamic registration                                                                                                                                | —                                                                                                                       |
| Session management and logout    | Session Management; Front-/Back-Channel Logout; RP-Initiated Logout | Not supported: no `sid`, no `end_session_endpoint`                                                                                                               | —                                                                                                                       |
| Self-Issued OP, WebFinger        | Core §7; Discovery §2                  | Not supported                                                                                                                                                                                  | —                                                                                                                       |

## Integration guide

### Wiring

```go
op, err := oidcprovider.New(oauth2.ServerConfig{
	Storage:        store,
	ClientStore:    clients,
	IssuerResolver: oauth2.StaticIssuer("https://op.example", "https://api.example"),
	ClientAuth:     []oauth2.ClientAuthenticator{clientauth.NewBasic(), clientauth.NewPost(), clientauth.NewNone()},
	Grants:         []oauth2.Grant{grant.NewAuthorizationCode(gcfg), grant.NewRefreshToken(gcfg)},
}, oidcprovider.Config{Keys: keys, Claims: app, Interaction: app})

paths, err := op.Paths("https://op.example")
srv := op.Server()
authorize := op.AuthorizeHandler(oauth2.AuthorizeConfig{})
mux.Handle("GET "+paths.Authorize, authorize)
mux.Handle("POST "+paths.Authorize, authorize)
mux.Handle("POST "+paths.Token, srv.TokenHandler())
mux.Handle("POST "+paths.Revoke, srv.RevokeHandler())
mux.Handle("POST "+paths.Introspect, srv.IntrospectHandler())
mux.Handle(paths.UserInfo, op.UserInfoHandler()) // GET and POST
mux.Handle("GET "+paths.Discovery, op.DiscoveryHandler())
mux.Handle("GET "+paths.Metadata, srv.MetadataHandler())
mux.Handle("GET "+paths.JWKS, op.JWKSHandler())
```

- `New` builds the `oauth2.Server` and registers the provider as its
  `Extension` (a server that already has one is refused, and so is one
  without the `authorization_code` grant).
- Mount the authorization endpoint through `Provider.AuthorizeHandler`: it
  owns the `ConsentFunc`, and an OpenID request served by
  `Server().AuthorizeHandler` directly is refused with `server_error` before
  any `ConsentFunc` runs.
- `Paths(issuer)` returns where to mount every handler: exactly the URLs the
  discovery document advertises — path issuers included
  (`/tenant/.well-known/openid-configuration`), and the RFC 8414 metadata at
  `/.well-known/oauth-authorization-server/tenant`. Revocation and
  introspection are advertised: mount them. Mount each handler at its
  `Paths` entry only, never under a catch-all pattern: the handlers do not
  check the request path (behind `http.StripPrefix` or a rewriting proxy
  they cannot see the public one), and relying parties require the
  discovery document's issuer to be the URL they fetched it from (Discovery
  §4.3) — a catch-all mounting would serve the issuer's document at any
  path.
- Wire `grant.Config.RefreshTokenScope = oidcprovider.ScopeOfflineAccess`:
  refresh tokens then only come with an `offline_access` the `Decision`
  granted, for OpenID and plain OAuth 2.0 requests alike. Only the scope is
  gated: without that wiring, a plain OAuth 2.0 grant — which carries no
  provider context — gets refresh tokens whatever its scope.
- CORS, when browsers call `/token` or UserInfo — UserInfo SHOULD support it
  (Core §5.3) — is the application's middleware: allow the clients' origins
  deliberately.

### The `Interaction` contract

`Interaction.Authorize(w, r, req)` serves an interactive request: render a
login or consent page and return `(nil, nil)`, or decide with a `Decision`.
The page sends the browser back to the authorization request when the
end-user is done, and `Authorize` runs again. `AuthorizeSilently(r, req)`
serves `prompt=none`: it has no `ResponseWriter`, and answers with a
`Decision` — an approval, or a `Refusal` such as `oauth2.ErrLoginRequired` or
`oauth2.ErrConsentRequired`, with the sentinel's own description: a refusal
travels to the client, and must not tell it what sessions the browser holds.

- `AuthenticationEvent` names the realm (`Issuer`, the issuer the session
  was established in), the `Subject` (1 to 255 printable ASCII characters),
  `AuthTime` (after the Unix epoch, not in the future), and optionally `ACR`
  and `AMR` (bounded). The provider refuses an event of another realm.
  Realms isolate sessions, not clients: see [Clients](#clients) for the
  clients of a multi-issuer deployment, and where tenancy is finer than the
  issuer — one issuer, several organizations — the `Interaction` also
  checks the session's tenant against `Request.Client`.
- `Request.Check(event, interactionStartedAt)` applies the request's rules —
  realm, `prompt=login`, `max_age`, designated end-user, essential `acr` —
  and returns the protocol error to refuse with. The provider re-checks
  every approval with it, so an application that ignores a rule gets the
  error, never a code. The check works at the second of `auth_time`: an
  application that must re-authenticate on `prompt=login` shows its login
  page itself (the example does).
- A login spanning several HTTP requests passes
  `Decision.InteractionStartedAt`: when the login of *this* authorization
  request began *in this browser*, kept in server-side state bound to both
  (keyed for instance by the browser's session and by `client_id`, `state`,
  `nonce` and `code_challenge`) — never read from the session's values or
  the request parameters: whoever knows a request's parameters must not be
  able to backdate its start for another browser. It must lie within
  `[ReceivedAt − MaxInteractionDuration, ReceivedAt + 5 s]`
  (`MaxInteractionDuration` is 15 minutes), and is ignored under
  `prompt=none`.
- `Decision.Scope` can only narrow the request and keeps `openid`;
  `Decision.Claims` names the requested claims the end-user releases;
  `Decision.OfflineAccess` grants a requested `offline_access`
  (`Request.OfflineAccess`, for every request) — `OfflineAccessPrompted`
  needs `prompt=consent` for an OpenID request, none for a plain OAuth 2.0
  one; without it, `offline_access` is dropped from the grant, and an
  approval left without any scope answers `access_denied`.
- The login and consent pages are the application's: a CSRF token on every
  form that carries a decision — not on the authorization endpoint, to
  which relying parties may POST their requests — no framing
  (`X-Frame-Options: DENY`, `frame-ancestors 'none'`), no caching, a
  return address limited to the authorization endpoint (never an open
  redirect), no `307` redirects, no page at all under `prompt=none`. The
  oauth2 core sets those headers, and `Referrer-Policy: same-origin`, on
  every response of the authorization endpoint — pages rendered behind it
  included; `same-origin` rather than `no-referrer`, under which browsers
  send `Origin: null` on the page's own POST. The example's pages do all of
  it, and the `app-hardening` scenarios of `e2e/oidc` check it through HTTP
  and a browser.

### Claims

`ClaimsSource.Claims` returns the claims of one end-user; `ClaimsQuery.Names`
lists the only ones the provider may release, and it drops anything else,
null and empty values, and every protocol claim (`sub`, `iss`, `aud`, `exp`,
`iat`, `auth_time`, `nonce`, `acr`, `amr`, `at_hash`, …). Returning
`ErrUnknownSubject` for an end-user that no longer exists or may no longer
sign in stops the grant — `invalid_grant` at `/token`, `invalid_token` at
UserInfo; any other error answers `server_error`. Disabling an end-user
must also revoke their token families: plain OAuth 2.0 grants carry no
OpenID context, and the source is not consulted for them.

`ClaimsQuery.Names` holds names the client chose in its `claims` parameter:
untrusted input, only known to be 1 to 255 bytes of UTF-8 without control
characters. A source that looks them up in a directory or a database
escapes or parameterizes them, or maps them through its own list.

**Case variants.** Claim names are case-sensitive (Core §5.1, RFC 7519 §4),
but relying parties often match them case-insensitively: Go's
`encoding/json` — go-oidc and most Go relying parties — reads `"SUB"` or
`"ſub"` (U+017F) as `sub`, the last member winning. The provider compares
names under a key that covers the rules of common relying parties — simple
case folding (`ſ`, the Kelvin sign), simple upper- and lower-case mappings
(`İ`, `ı`: Java's `equalsIgnoreCase`), full case mappings (`ß` as `ss`, the
`ﬁ` ligatures: upper-casing in JavaScript, Java, Python), the diacritics
lodash's `camelCase` strips from Latin letters (`émail` as `email`), and
ignoring every character but letters, decimal digits and `#` — punctuation,
white space, invisible characters and marks (`encoding/json/v2` with
`case:ignore` ignores `_` and `-`; camelCase key normalizers — lodash
`camelCase`, `camelcase-keys`, humps — read `email.verified`,
`email verified` or `email‐verified` (U+2010) as `emailVerified`) — and
never releases, nor asks the source for:

- a case variant of a protocol claim, or of a claim reserved to another
  protocol (`azp`, `jti`, `sid`, `scope`, …);
- another spelling of a claim it knows: the standard claims (Core §5.1),
  `roles`, `groups` and `entitlements` (RFC 9068 §2.2.3.1), and
  `Config.ClaimsSupported` — `Email`, `e_mail` and `EMAIL#fr` are dropped,
  `email#fr` is released;
- claims whose names are case variants of one another in one response: all
  of them, since which one a relying party would read is unknowable;
- a name that is not 1 to 255 bytes of UTF-8 without control characters
  (two invalid names would be written as the same member twice);
- a value holding, at any depth, an object with two member names that are
  case variants of each other (exact duplicates included) or a member name
  in invalid UTF-8 or with a control character, an unpaired surrogate
  escape, a number beyond float64, or more than 31 levels of nesting:
  relying parties refuse a whole token or document holding one —
  `oidc/client` the token, `encoding/json` decoding into an `any` the
  document.

Dropping a claim is never an error (Core §5.3.2, §5.5). The `Interaction` is
only shown the claim requests the provider may release (`Request.Claims`),
and the grant records only those; the rules apply again at every exchange
and at UserInfo, so a grant recorded earlier follows the current
configuration. Declare every application claim relying parties make
decisions on in `Config.ClaimsSupported`: an undeclared claim requested
alone under another spelling is released under that spelling (a relying
party may read it as the claim it expects), and requested together with a
variant it is dropped (an end-user can suppress it). `New` refuses a
`ClaimsSupported` entry the provider never releases or that is a case
variant of a protocol, standard or other entry's claim.

### Keys and rotation

A `KeySource` returns each issuer's `KeyRing` on every use — the provider
validates it every time and fails closed. Cache in the implementation (a
KMS, a database). `KeyRing.Signing` holds one private key per algorithm, an
RS256 key among them; `KeyRing.Published` holds further public keys the JWK
Set publishes. Rotate without breaking a relying party:

1. publish the next key (`Published`) and wait for relying parties to
   refresh their cached key sets;
2. sign with it (move it to `Signing`, publish the retired one);
3. drop the retired key once every ID Token it signed has expired
   (`Config.IDTokenTTL`, one hour by default) and no `id_token_hint` needs it.

How long step 1 waits depends on the relying parties' caches. The JWK Set
answers with `Cache-Control: max-age=300`; `oidc/client` keeps a set for an
hour and refetches it at most every 10 seconds on an unknown `kid`
([oidc-client.md](oidc-client.md#provider-keys-and-rotation)); go-oidc
refetches on any unknown `kid`. Wait at least an hour — more if a relying
party you know caches longer — between steps 1 and 2: a key that signs
before a relying party learned it fails that relying party's logins until
it refetches (stack: `TestAbruptRotationWithinTheRefreshInterval`).
Withdrawing a leaked key is not instantaneous either: `oidc/client` keeps
accepting it until its cached set is an hour old (stack:
`TestKeyWithdrawalWindow`); ask the relying parties to rebuild their
clients.

The keys of JWT access tokens belong in `Published` too: one `jwks_uri`
serves both (RFC 9068 §4). Their audiences must never be client IDs.

### Clients

Clients are static (`oauth2.ClientStore`) and get only what they declare:
an OpenID client declares `openid` among its scopes — plus every other
scope it requests (`offline_access`, `profile`, `email`…), an empty list
allowing none — and `authorization_code` among its grant types, with
`refresh_token` to receive refresh tokens (an empty list allows no grant).
It has exact redirect URIs, and optionally implements
`IDTokenSigningClient` to choose its ID Token algorithm — the issuer's ring
must then hold a key of that algorithm.

With several issuers (tenants) and one `ClientStore`, every client is known
at every issuer: a client of tenant A could send tenant B's end-users to
B's genuine login page and obtain their identity and B's tokens once they
consent — separate issuers isolate sessions, not clients. Register each
client at its issuers: implement `oauth2.IssuerBoundClient` on your client
type, or fill `oauth2.DefaultClient.IssuerValues`, or scope the
`ClientStore` by issuer. At any other issuer the client then does not
exist: the authorization endpoint answers the bare 400 of an unknown
client before any interaction, and `/token`, `/revoke`, `/introspect` fail
its authentication as an unknown client's; UserInfo refuses a token whose
client is no longer registered at the issuer.

### Upgrades

The provider records the authentication event and the released claims with
every grant, as a versioned context. A context the running version cannot
read — written by a newer version, after a rollback — refuses the grant with
`invalid_grant`: the end-user signs in again.

### Errors

Every refusal reaches the server's `ErrorHook` (`ServerConfig.OnError`) as an
`*oauth2.Error` with its cause. Causes never carry a token, a hint, a nonce
or a claim value. The provider emits no span of its own; see
[observability.md](observability.md).
