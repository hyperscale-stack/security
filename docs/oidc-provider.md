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
pages with CSRF tokens, sessions, `prompt` handling, offline access.

## Conformance status

No certification and no blanket conformance claim: this page lists, row by
row, what is supported, how, and the tests that prove it. Runs of the
OpenID Foundation conformance suite are tracked separately (#86) and are not
a certification either. Interoperability is checked in CI against an
independent relying party — `github.com/coreos/go-oidc/v3` v3.21.0 and
`golang.org/x/oauth2` v0.37.0, in the test-only module
`internal/interop/oidcop` (never a dependency of a production module).

Test names refer to `oidc/provider` unless prefixed with `interop:`
(`internal/interop/oidcop`), `oauth2:` or `jwt:`.

## Feature matrix

### Flows and requests

| Capability                                  | Spec                               | Status                                                                                                                                                                                                                               | Tests                                                                                                                   |
| ------------------------------------------- | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------- |
| Authorization Code flow                     | Core §3.1                          | Supported                                                                                                                                                                                                                            | `TestIDTokenClaims`, interop: `TestInteropCodeFlowS256`                                                                 |
| PKCE                                        | RFC 7636                           | As the core's `Profile` decides: `S256` required under `Profile20BCP` (default) and `Profile21Draft`; optional under `Profile20`, which also allows `plain`                                                                          | `TestDiscoveryPKCEMethodsFollowTheProfile`, interop: `TestInteropPublicClient`                                          |
| Plain OAuth 2.0 requests (no `openid`)      | Core §3.1.2.1                      | Unchanged OAuth 2.0 semantics: no ID Token, no UserInfo, realm rule only                                                                                                                                                             | `TestPlainOAuth2RequestKeepsOAuth2Semantics`, `TestPlainOAuth2CodeExchange`, `TestRefreshOfAPlainOAuth2Grant`           |
| Implicit and hybrid flows                   | Core §3.2, §3.3                    | Not supported, not advertised: an OpenID request with another `response_type` gets `unsupported_response_type`                                                                                                                      | `TestOpenIDImplicitRefused`                                                                                             |
| Response modes                              | Core §3.1.2.1; OAuth 2.0 Multiple Response Types | `query` only (advertised); the core refuses any other with a bare `400`, never redirected                                                                                                                              | `TestDiscoveryDocument`, oauth2: `TestAuthorizeRefusesUnsupportedResponseModes`                                                                   |
| `redirect_uri`                              | Core §3.1.2.1                      | REQUIRED for OpenID requests: missing → `400`, never redirected                                                                                                                                                                      | `TestOpenIDRequestWithoutRedirectURIIsNotRedirected`                                                                    |
| Repeated parameters                         | RFC 6749 §3.1                      | Refused: `client_id`, `redirect_uri`, `response_mode` → `400`, never redirected; any other → `invalid_request`. An empty value is no occurrence, except as the first value of a core parameter                                        | `TestDuplicatedParameters`                                                                                              |
| `nonce`                                     | Core §3.1.2.1, §2                  | Optional (code flow); at most 512 bytes of UTF-8 without NUL, else `invalid_request`; in the ID Token of the code exchange only                                                                                                      | `TestNonceBounds`, `TestIDTokenClaims`, `TestIDTokenWithoutNonceHasNoNonce`                                             |
| `prompt`                                    | Core §3.1.2.1                      | `none`, `login`, `consent`, `select_account` reach the `Interaction`; unknown values ignored; `none` with another value → `invalid_request`                                                                                          | `TestPromptParsing`                                                                                                     |
| `prompt=none`                               | Core §3.1.2.1, §3.1.2.6            | `Interaction.AuthorizeSilently` only — it has no `ResponseWriter`; its refusals (`login_required`, `consent_required`, `interaction_required`, `account_selection_required`) are redirected                                        | `TestPromptNoneIsSilent`, `TestPromptNoneRefusals`, `TestPromptNoneWithoutDecisionIsAServerError`, interop: `TestInteropPromptNone` |
| `prompt=login`                              | Core §3.1.2.1                      | Enforced by the provider: an authentication older than the request (to the second of `auth_time`) → `login_required`                                                                                                              | `TestFreshnessIsEnforcedByTheProvider`, `TestRequestCheck`                                                              |
| `max_age`                                   | Core §3.1.2.1, §2                  | Enforced (`auth_time + max_age` ≥ request time, to the second); `1*DIGIT`, longer values clamped to 2³¹−1 s, anything else → `invalid_request`; `auth_time` always in the ID Token                                                | `TestMaxAgeParsing`, `TestFreshnessIsEnforcedByTheProvider`, `TestIDTokenCarriesTheAuthenticationEvent`                 |
| `id_token_hint`                             | Core §3.1.2.1, §3.1.2.2            | Verified: signed by a key the issuer publishes, `iss` the issuer, the client among its audiences, a `sub`, typed `JWT` or untyped (an `at+jwt` is refused); its expiry is not checked. It designates the end-user (another one → `login_required`). Invalid → `invalid_request` | `TestIDTokenHint`, `TestIDTokenHintOfARetiredKey`, `TestIDTokenHintDesignatesTheEndUser`                                |
| `login_hint`, `display`, `ui_locales`, `claims_locales`, `acr_values` | Core §3.1.2.1, §5.2, §15.1 | Passed to the `Interaction`, bounded; never fail a request; `acr_values` is voluntary                                                                                                                       | `TestPassthroughParameters`, `TestVoluntaryACRIsNotEnforced`                                                            |
| `claims` parameter                          | Core §5.5, §5.5.1                  | Supported (advertised): strict JSON, bounded; a requested claim is released only when the end-user agrees (`Decision.Claims`) and its value matches a `value`/`values` constraint                                                  | `TestClaimsParameterParsing`, `TestClaimsParameterRefusals`, `TestReleasedClaims`, `TestValueConstraintsMatchScalarsOnly` |
| Essential `acr`                             | Core §5.5.1.1                      | Enforced: unmet → `access_denied`, `login_required` under `prompt=none`                                                                                                                                                               | `TestEssentialACRIsEnforced`, `TestRequestCheck`                                                                        |
| `sub` claim request                         | Core §5.5.1                        | Designates the end-user, like a hint; conflicting designations → `invalid_request`                                                                                                                                                  | `TestClaimsParameterDerivedRequirements`, `TestIDTokenHintDesignatesTheEndUser`                                         |
| `request`, `request_uri`                    | Core §6                            | Not supported: `request_not_supported`, `request_uri_not_supported`; advertised as unsupported                                                                                                                                      | `TestRequestObjectParametersRefused`, `TestDiscoveryDocument`                                                           |
| `registration` parameter                    | Core §7.2.1                        | Not supported: `registration_not_supported`                                                                                                                                                                                          | `TestRequestObjectParametersRefused`                                                                                    |
| Realm of the authentication                 | Core §16.15                        | `AuthenticationEvent.Issuer` must be the request's issuer: else `login_required` (OpenID) or `access_denied` (OAuth 2.0)                                                                                                            | `TestRealmIsEnforced`, `TestRequestCheck`                                                                               |
| Consent                                     | Core §3.1.2.4                      | `Decision`: approval, `Scope` narrowing (keeps `openid`), `Claims`, `Refusal`; an empty decision → `access_denied`                                                                                                                 | `TestDecisionScopeNarrows`, `TestInteractionFailures`, `TestApprovalContractViolations`                                 |
| `offline_access`                            | Core §11                           | Granted only with consent — the `prompt=consent` dialog (`OfflineAccessPrompted`) or the application's policy (`OfflineAccessByPolicy`) — else dropped from the grant. A refresh token without that consent fails closed (`server_error` at issuance, `invalid_grant` at refresh) unless `Config.AllowRefreshWithoutOfflineAccess` | `TestOfflineAccessRequiresConsent`, `TestRefreshWithoutOfflineConsentFailsClosed`, interop: `TestInteropRefresh`        |

### ID Tokens and refresh

| Capability                       | Spec                                 | Status                                                                                                                                                                                       | Tests                                                                                               |
| -------------------------------- | ------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| ID Token claims                  | Core §2, §3.1.3.6                    | `iss`, `sub`, `aud` (the client ID, a string), `exp`, `iat`, `auth_time` (always), `nonce` (code exchange), `acr` and `amr` (from the event), `at_hash`; no `azp` (one audience)              | `TestIDTokenClaims`, `TestIDTokenCarriesTheAuthenticationEvent`                                     |
| Signing algorithms               | Core §15.1, §16.14; Registration §2  | RS256 (mandatory, default), RS384/512, PS256/384/512, ES256/384/512 per client (`IDTokenSigningClient`); never `none`, HS* or EdDSA. No key for the client's algorithm → `server_error` before any interaction | `TestIDTokenSigningAlgorithms`, `TestClientWithoutAnAlgorithmGetsRS256`, `TestClientAlgorithmWithoutAKey` |
| Application claims               | Core §5.4, §5.5                      | Only the claims requested through `claims` and released; protocol claims never come from the source; null and empty strings dropped. Scope claims (`profile`, `email`, …) go to UserInfo only | `TestIDTokenClaimsFromTheClaimsParameter`, `TestValueConstraintsMatchScalarsOnly`                   |
| Code issued for OpenID           | Core §3.1.3.2                        | An `openid` code without the provider's context → `invalid_grant`                                                                                                                            | `TestOpenIDCodeWithoutContextIsRefused`                                                             |
| Account validity                 | —                                    | `ClaimsSource` queried on every exchange of an OpenID grant: `ErrUnknownSubject` → `invalid_grant`                                                                                          | `TestCodeExchangeFailures`, `TestRefreshChecksTheAccountEvenWithoutOpenID`                          |
| Token confusion                  | RFC 9068 §5, RFC 8725 §3.12          | An access-token audience equal to the client ID → `server_error`; JWT access tokens are typed `at+jwt`                                                                                      | `TestCodeExchangeFailures`, jwt: `TestOAuth2AccessTokenSignerFollowsRFC9068`                        |
| Refresh                          | Core §12.2                           | An ID Token at every refresh of an OpenID grant: same `iss`, `sub`, `aud`; new `iat`; the original `auth_time`, `acr`, `amr`; no `nonce`; none once the scope drops `openid`                | `TestRefreshIDTokensFollowCore12_2`, `TestRefreshWithoutOpenIDHasNoIDToken`, interop: `TestInteropRefresh` |
| Encrypted ID Tokens              | Core §10.2                           | Not supported, not advertised                                                                                                                                                                | —                                                                                                   |

### UserInfo

| Capability                       | Spec                              | Status                                                                                                                                                                                                | Tests                                                                                     |
| -------------------------------- | --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Transport                        | Core §5.3.1; RFC 6750 §2          | GET and POST; bearer token in the `Authorization` header or a form-encoded POST body; a URI query token is not supported (ignored alone, a second method otherwise)                                  | `TestUserInfoMethods`, `TestUserInfoTokenMethods`                                         |
| Token validation                 | Core §5.3; RFC 6750 §3.1          | b64token syntax, known and outside a revoked family, unexpired, issued under the request's issuer to an OpenID grant, scope holding `openid`                                                         | `TestUserInfoErrors`, `TestUserInfoRefusesUnusableRecords`                                |
| Errors                           | RFC 6750 §3, §3.1; Core §5.3.3    | `WWW-Authenticate: Bearer realm="<issuer>"`: no error information without a token, `invalid_request` (400), `invalid_token` (401), `insufficient_scope` (403, `scope="openid"`); server failures 500 | `TestUserInfoErrors`, `TestUserInfoTokenMethods`, `TestUserInfoErrorsReachTheHook`        |
| Claims                           | Core §5.3.2, §5.4, §5.5           | The access token's scope claims and the released `userinfo` claim requests; `sub` is the token's — the ID Token's; JSON, `Cache-Control: no-store`                                                 | `TestUserInfoScopeClaims`, `TestUserInfoClaimsParameter`, `TestUserInfoSubMatchesIDToken`, `TestUserInfoHeaders` |
| Signed or encrypted UserInfo     | Core §5.3.2                       | Not supported, not advertised                                                                                                                                                                          | —                                                                                         |
| Aggregated and distributed claims | Core §5.6.2                      | Not supported                                                                                                                                                                                          | —                                                                                         |

### Discovery, keys, issuers and clients

| Capability                       | Spec                                   | Status                                                                                                                                                                                         | Tests                                                                                                                   |
| -------------------------------- | -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| Discovery                        | Discovery §3, §4                       | Per-request issuer, path issuers (§4.1); advertises only what is served; consistent with the RFC 8414 metadata                                                                                | `TestDiscoveryDocument`, `TestDiscoveryPathIssuers`, `TestDiscoveryConsistentWithRFC8414Metadata`, interop: `TestInteropDiscoveryMetadata`, `TestAdvertisedURLsAreServed` |
| Mix-up defense                   | RFC 9207                               | Every authorization response carries `iss` (except the `server_error` of a failed `IssuerResolver`); advertised                                                                              | oauth2: `TestAuthorizationResponsesNameTheIssuer`, interop: `TestInteropCodeFlowS256`                                    |
| JWK Set                          | RFC 7517; Core §10.1.1                 | Public signature keys only, per issuer; rotation through `KeyRing.Published`                                                                                                                  | `TestJWKSPublishesPublicKeysOnly`, `TestJWKSIsPerIssuer`, `TestKeyRotationThroughJWKS`, interop: `TestInteropKeyRotation` |
| Key rings                        | RFC 7518 §3; RFC 8725 §3.1             | RS256 key required; one key per algorithm and one algorithm per key; RSA ≥ 2048 bits, curves bound to algorithms, unique `kid`s; no private or symmetric key published; validated on every use | `TestKeyRingValidate`, `TestJWKSFailsClosed`                                                                            |
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
  introspection are advertised: mount them.
- Wire `grant.Config.RefreshTokenScope = oidcprovider.ScopeOfflineAccess`:
  refresh tokens then only come with a consented `offline_access`.
- CORS, when browsers call `/token` or UserInfo, is the application's
  middleware.

### The `Interaction` contract

`Interaction.Authorize(w, r, req)` serves an interactive request: render a
login or consent page and return `(nil, nil)`, or decide with a `Decision`.
The page sends the browser back to the authorization request when the
end-user is done, and `Authorize` runs again. `AuthorizeSilently(r, req)`
serves `prompt=none`: it has no `ResponseWriter`, and answers with a
`Decision` — an approval, or a `Refusal` such as `oauth2.ErrLoginRequired` or
`oauth2.ErrConsentRequired`.

- `AuthenticationEvent` names the realm (`Issuer`, the issuer the session
  was established in), the `Subject` (1 to 255 printable ASCII characters),
  `AuthTime` (not in the future), and optionally `ACR` and `AMR` (bounded).
  The provider refuses an event of another realm; where tenancy is finer
  than the issuer, the `Interaction` also checks the session's tenant
  against `Request.Client`.
- `Request.Check(event, interactionStartedAt)` applies the request's rules —
  realm, `prompt=login`, `max_age`, designated end-user, essential `acr` —
  and returns the protocol error to refuse with. The provider re-checks
  every approval with it, so an application that ignores a rule gets the
  error, never a code. The check works at the second of `auth_time`: an
  application that must re-authenticate on `prompt=login` shows its login
  page itself (the example does).
- A login spanning several HTTP requests passes
  `Decision.InteractionStartedAt`: when the login of *this* authorization
  request began, kept in server-side state bound to the request (keyed for
  instance by `client_id`, `state`, `nonce` and `code_challenge`) — never
  read from the session or the request parameters. It must lie within
  `[ReceivedAt − MaxInteractionDuration, ReceivedAt + 5 s]`
  (`MaxInteractionDuration` is 15 minutes), and is ignored under
  `prompt=none`.
- `Decision.Scope` can only narrow the request and keeps `openid`;
  `Decision.Claims` names the requested claims the end-user releases;
  `Decision.OfflineAccess` grants a requested `offline_access` —
  `OfflineAccessPrompted` only for a request with `prompt=consent`.

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

The keys of JWT access tokens belong in `Published` too: one `jwks_uri`
serves both (RFC 9068 §4). Their audiences must never be client IDs.

### Clients

Clients are static (`oauth2.ClientStore`). An OpenID client has `openid`
among its scopes, exact redirect URIs, and optionally implements
`IDTokenSigningClient` to choose its ID Token algorithm — the issuer's ring
must then hold a key of that algorithm.

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
