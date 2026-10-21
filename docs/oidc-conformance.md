# OpenID Connect: conformance coverage and interoperability

A local run of the OpenID Foundation conformance suite is not an OpenID
Certification and is not presented as one.

This page gathers, for the OpenID Provider (`oidc/provider`,
[oidc-provider.md](oidc-provider.md)) and the Relying Party (`oidc/client`,
[oidc-client.md](oidc-client.md)), what is supported, what is not, and the
evidence: tests in CI, independent implementations, opt-in end-to-end and
conformance-suite runs, with their results and gaps. Specifications: OpenID
Connect Core 1.0 (errata set 2) and Discovery 1.0 for the Authorization
Code flow, with RFC 6749, RFC 6750, RFC 7636, RFC 8725, RFC 9068, RFC 9207
and the OAuth 2.0 Security BCP (RFC 9700).

## Evidence

| Layer                       | Where                                                         | Runs                         | What it shows                                                                                   |
| --------------------------- | ------------------------------------------------------------- | ---------------------------- | ----------------------------------------------------------------------------------------------- |
| Unit and protocol tests     | `oidc/provider`, `oidc/client`, `oauth2`, `jwt`               | CI                           | every rule of the matrices below, with fakes                                                    |
| Our client against our provider | `internal/interop/oidcstack`                              | CI                           | complete flows over HTTP, attacks and failures across both modules                              |
| Independent implementations | `internal/interop/oidcop`, `internal/interop/oidcrp`          | CI                           | our provider through go-oidc + x/oauth2; our client against zitadel/oidc and real metadata      |
| Real stores                 | `internal/interop/oidcstack` (`TestRealBackend*`)             | CI (`make test-backends`)    | atomic consumption of login transactions on PostgreSQL 16, MySQL 8.0, Redis 7.4                |
| Browser end to end          | `e2e/oidc` (Tales), `internal/interop/oidcrp` (chromedp)      | opt-in, local                | the two examples through HTTP and a real Chrome; SameSite behaviour of the binding cookie       |
| OpenID Foundation suite     | `internal/interop/oidcstack/conformance` (`make conformance`) | opt-in, local                | the suite's OP and RP plans, every module's result pinned                                       |
| Live                        | `OIDC_LIVE_DISCOVERY=1`, `make e2e-oidc-live`                 | opt-in, manual               | real providers' metadata; a real account's sign-in                                              |

In the tables, test names refer to `oidc/provider` (column Provider) or
`oidc/client` (column Client) unless prefixed: `oauth2:`, `jwt:`,
`stack:` (`internal/interop/oidcstack`), `interop:`
(`internal/interop/oidcop`), `rp:` (`internal/interop/oidcrp`); `e2e:`
names an `e2e/oidc` file, `suite:` a module of the OpenID Foundation suite.

## Supported profile

- Authorization Code flow with PKCE S256 (`plain` and challenge-less
  requests refused by the default profile; a `code_verifier` is never
  accepted for a code issued without challenge), `state`, `nonce`, RFC 9207
  `iss` in every authorization response.
- Response modes: the provider serves `query`; the client accepts `query`
  and `form_post`.
- Client authentication: `client_secret_basic` (form-urlencoded
  credentials), `client_secret_post`, `none` (public clients, PKCE only).
- ID Tokens signed with RS256 (mandatory), RS384/512, PS256/384/512,
  ES256/384/512 — and EdDSA on the client side; never HMAC or `none`.
- `prompt`, `max_age`, `id_token_hint`, `login_hint`, `ui_locales`,
  `claims_locales`, `display`, `acr_values`; the `claims` parameter on the
  provider side.
- UserInfo (GET and POST, Bearer header and — provider — form body),
  Discovery with path issuers, the JWK Set with rotation, refresh tokens
  with rotation and reuse detection (`offline_access`).

## Requirements matrix

| #   | Requirement                                                                                  | Provider                                                                                                                                                       | Client                                                                                                                 | Across implementations                                                                                                                                                                 |
| --- | -------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| R1  | Authorization Code flow, `response_type=code`, `openid` scope (Core §3.1, §3.1.2.1)          | `TestIDTokenClaims`, `TestPlainOAuth2RequestKeepsOAuth2Semantics`, `TestOpenIDImplicitRefused`                                                                 | `TestBeginParameters`, `TestCompleteQuery`, `TestEndToEndQuery`                                                        | stack: `TestCodeFlowAgainstOurProvider`; interop: `TestInteropCodeFlowS256`; rp: `TestZitadelCodeFlow`; e2e: `provider_code_flow`; suite: `oidcc-server`, `oidcc-client-test`       |
| R2  | `redirect_uri` exact, required for OpenID, unregistered never redirected (RFC 6749 §3.1.2, RFC 9700 §4.1) | `TestOpenIDRequestWithoutRedirectURIIsNotRedirected`                                                                                                | `TestCompleteTransactionMismatch`, `TestCompleteRootRedirect`, `TestCompleteCallbackURL`                               | stack: `TestMixUpWithAnAttackerProvider`; e2e: `provider_errors`; suite: `oidcc-ensure-registered-redirect-uri`                                                                       |
| R3  | `state`, login CSRF, browser binding (RFC 6749 §10.12, RFC 9700 §4.7)                         | —                                                                                                                                                              | `TestCompleteBinding`, `TestStartLoginCookie`, `TestParallelLogins`                                                    | rp: `TestBrowserBindingCookie`; stack: `TestCodeInjectionIsDefeated`, `TestParallelLoginsStayIsolated`; e2e: `rp_callback`, `browser_cross_site`                                    |
| R4  | `nonce` echoed and checked (Core §3.1.2.1, §3.1.3.7, §15.5.2)                                 | `TestNonceBounds`, `TestIDTokenWithoutNonceHasNoNonce`                                                                                                         | `TestIDTokenNonce`                                                                                                     | stack: `TestResignedIDTokensAreRefused`, `TestTokenResponseSubstitution`; suite: `oidcc-client-test-nonce-invalid`, `oidcc-ensure-request-without-nonce-succeeds-for-code-flow`      |
| R5  | PKCE S256, verifier and challenge syntax (RFC 7636)                                           | `TestDiscoveryPKCEMethodsFollowTheProfile`; oauth2: `TestAuthorizeRejectsMalformedS256Challenge`, `TestAuthorizationCodeRejectsMalformedVerifier`            | `TestBeginChallengeMatchesVerifier`, `TestCapabilities`                                                                | stack: `TestCodeInjectionIsDefeated`; interop: `TestInteropPublicClient`; e2e: `provider_code_flow`; suite: `oidcc-ensure-request-with-valid-pkce-succeeds`                         |
| R6  | PKCE downgrade refused (RFC 9700 §2.1.1, §4.8.2)                                              | oauth2: `TestAuthorizationCodeRefusesAVerifierWithoutAChallenge`, `TestAuthorizationCodeDowngradeRefusalKeepsReplayRevocation`                                | never omits S256                                                                                                       | stack: `TestPKCEDowngradeIsRefused`; e2e: `provider_errors`                                                                                                                           |
| R7  | Client authentication: basic (form-urlencoded), post, none (Core §9, RFC 6749 §2.3.1)         | oauth2: `TestBasicDecodesFormURLEncodedCredentials`                                                                                                            | `TestTokenClientAuthentication`                                                                                        | stack: `TestCodeFlowAgainstOurProvider`; interop: `TestInteropClientSecretPost`; e2e: `provider_errors`; suite: `oidcc-server-client-secret-post`, `oidcc-client-test-client-secret-basic` |
| R8  | ID Token claims (Core §2, §3.1.3.6)                                                           | `TestIDTokenClaims`, `TestIDTokenCarriesTheAuthenticationEvent`, `TestProtocolClaimsCannotBeAliasedByCaseVariants`                                                                                                | `TestIDTokenIssuerAndSubject`, `TestIDTokenAudience`, `TestIDTokenTimes`, `TestIDTokenAccessTokenHash`                | stack: `TestCodeFlowAgainstOurProvider`; interop: `TestInteropCaseVariantClaimsNeverReachTheRP`; suite: `oidcc-client-test-missing-sub`, `-missing-iat`, `-invalid-aud`, `-invalid-iss`                                                    |
| R9  | ID Token validation (Core §3.1.3.7, RFC 8725 §3.1, §3.11)                                     | —                                                                                                                                                              | `TestIDTokenAlgorithms`, `TestIDTokenHeader`, `TestIDTokenKeySelection`, `TestIDTokenSignature`, `TestIDTokenClaimsJSON` | stack: `TestResignedIDTokensAreRefused`, `TestUnknownKeysTriggerABoundedRefresh`; suite: `oidcc-client-test-invalid-sig-rs256`, `-invalid-sig-hs256`, `-invalid-sig-es256`, `-kid-absent-*` |
| R10 | Signing algorithms, RS256 mandatory, never `none` or HMAC (Core §15.1, §16.14)               | `TestIDTokenSigningAlgorithms`, `TestKeyRingValidate`, `TestClientWithoutAnAlgorithmGetsRS256`                                                                | `TestIDTokenAlgorithms`                                                                                                | stack: `TestCodeFlowSigningAlgorithms`; interop: `TestInteropSigningAlgorithms`; suite: `oidcc-client-test-idtoken-sig-rs256`, `-idtoken-sig-none`                                 |
| R11 | `prompt` (Core §3.1.2.1, §3.1.2.6)                                                           | `TestPromptParsing`, `TestPromptNoneIsSilent`, `TestPromptNoneRefusals`, `TestRequestCheck`                                                                   | `TestBeginRefusesInvalidOptions`, `TestCompleteAuthorizationError`                                                    | stack: `TestPromptNoneThroughTheClient`, `TestRefusalsRevealNoSession`; interop: `TestInteropPromptNone`; e2e: `provider_prompt`; suite: `oidcc-prompt-login`, `oidcc-prompt-none-*` |
| R12 | `max_age` and `auth_time` (Core §3.1.2.1)                                                    | `TestMaxAgeParsing`, `TestFreshnessIsEnforcedByTheProvider`                                                                                                   | `TestIDTokenAuthTime`                                                                                                  | stack: `TestReauthenticationThroughTheClient`; interop: `TestInteropReauthentication`; e2e: `provider_prompt`; suite: `oidcc-max-age-1`, `oidcc-max-age-10000`                    |
| R13 | `id_token_hint`, `login_hint`, locales, `display`, `acr_values` (Core §3.1.2.1)               | `TestIDTokenHint`, `TestIDTokenHintDesignatesTheEndUser`, `TestPassthroughParameters`, `TestVoluntaryACRIsNotEnforced`                                        | `TestBeginHints`, `TestIDTokenACR`                                                                                     | stack: `TestHintsReachTheProvider`, `TestACRValuesThroughTheClient`; interop: `TestInteropIDTokenHint`; rp: `TestZitadelACRValues`; suite: `oidcc-id-token-hint`, `oidcc-login-hint`, `oidcc-ui-locales`, `oidcc-claims-locales`, `oidcc-display-*` |
| R14 | Consent, scope narrowing, `claims` parameter (Core §3.1.2.4, §5.4, §5.5)                      | `TestReleasedClaims`, `TestKnownClaimsAreReleasedUnderTheirExactSpellingOnly`, `TestClaimNamesCollidingUnderCaseFoldingAreDropped`, `TestTheInteractionIsShownReleasableClaimRequestsOnly`, `TestDecisionScopeNarrows`, `TestClaimsParameterParsing`, `TestValueConstraintsMatchScalarsOnly`, `TestEssentialACRIsEnforced`         | the `claims` parameter is not supported                                                                                | stack: `TestGrantedScopeDrivesUserInfo`, `TestConsentDeniedThroughTheClient`; interop: `TestInteropClaimsParameter`, `TestInteropConsentNarrowsScope`; e2e: `provider_consent_refresh`; suite: `oidcc-scope-*`, `oidcc-claims-essential` |
| R15 | UserInfo, `sub` equal to the ID Token's (Core §5.3, RFC 6750 §2, §3)                          | `TestUserInfoMethods`, `TestUserInfoTokenMethods`, `TestUserInfoErrors`, `TestUserInfoSubMatchesIDToken`, `TestProtocolClaimsCannotBeAliasedByCaseVariants`, `TestUserInfoScopeClaims`                          | `TestUserInfo`, `TestUserInfoResponses`, `TestUserInfoSubjectIsCaseSensitive`, `TestUserInfoRefusesForeignIdentity`    | stack: `TestUserInfoSubstitution`; e2e: `provider_code_flow`, `provider_errors`; suite: `oidcc-userinfo-get`, `-post-header`, `-post-body`, `oidcc-client-test-userinfo-invalid-sub` |
| R16 | Refresh, `offline_access` (Core §11, §12.2)                                                   | `TestRefreshIDTokensFollowCore12_2`, `TestOfflineAccessRequiresConsent`, `TestPlainOAuth2OfflineAccessNeedsTheDecision`, `TestRefreshWithoutOfflineConsentFailsClosed`; oauth2: `TestRefreshTokenRotationDetectsReuse` | refresh tokens returned raw                                                                                          | stack: `TestRefreshOfAClientLogin`, `TestRefreshReuseRevokesTheClientsTokens`; interop: `TestInteropRefresh`, `TestInteropRefreshReuse`; e2e: `provider_consent_refresh`; suite: `oidcc-refresh-token` |
| R17 | Discovery, path issuers, exact issuer (Discovery §3, §4)                                      | `TestDiscoveryDocument`, `TestDiscoveryPathIssuers`, `TestDiscoveryConsistentWithRFC8414Metadata`, `TestIssuerValidation`                                      | `TestDiscoveryURL`, `TestIssuerMismatch`, `TestRequiredMetadata`, `TestEndpointURLs`, `TestStrictMetadataJSON`        | stack: `TestCodeFlowAgainstOurProvider`; interop: `TestInteropDiscoveryMetadata`, `TestAdvertisedURLsAreServed`; rp: `TestProviderMetadataCorpus`; suite: `oidcc-discovery-endpoint-verification`, `oidcc-client-test-discovery-*` |
| R18 | JWK Set, rotation with overlap, bounded relying-party refresh (Core §10.1.1, RFC 7517)       | `TestJWKSPublishesPublicKeysOnly`, `TestPathIssuersUseTheirOwnKeyRings`, `TestKeyRotationThroughJWKS`, `TestJWKSFailsClosed`                                                                        | `TestKeyRotation`, `TestUnknownKidIsRateLimited`, `TestKeySetTTL`, `TestKeySetStaleOnFailure`, `TestNoRefetchOnBadSignature` | stack: `TestDocumentedRotationIsInvisibleToTheClient`, `TestAbruptRotationWithinTheRefreshInterval`, `TestKeyWithdrawalWindow`, `TestJWKSOutage`; interop: `TestInteropKeyRotation`; suite: `oidcc-client-test-signing-key-rotation*` |
| R19 | RFC 9207 `iss` in every authorization response, required when advertised                     | oauth2: `TestAuthorizationResponsesNameTheIssuer`, `TestIssuerResolverFailureCannotNameTheIssuer`                                                              | `TestCompleteIssParameter`                                                                                             | stack: `TestMixUpBetweenIssuersOfOneProvider`, `TestIssuerResolverFailureReachesTheClientWithoutIss`; interop: `TestInteropCodeFlowS256`                                          |
| R20 | Mix-up defense (RFC 9700 §4.4)                                                               | —                                                                                                                                                              | `TestCompleteMixUp`                                                                                                    | stack: `TestMixUpWithAnAttackerProvider`, `TestMixUpResidualWithoutRFC9207`                                                                                                           |
| R21 | Realm and tenant isolation (Core §16.15)                                                      | `TestRealmIsEnforced`; oauth2: `TestCodeRedeemedAtAnotherIssuerIsRefused`, `TestRefreshAtAnotherIssuerIsRefused`, `TestBoundClientIsUnknownAtAnotherIssuer`, `TestBoundClientCannotAuthenticateAtAnotherIssuer` | `TestCompleteTransactionMismatch`                                                                    | stack: `TestClientBoundToAnotherIssuer`, `TestMixUpBetweenIssuersOfOneProvider`, `TestRefusalsRevealNoSession`; interop: `TestInteropPathIssuers`                                 |
| R22 | Code single use, replay revokes (RFC 6749 §4.1.2, RFC 9700 §4.5)                             | oauth2: `TestTokenEndpointCodeReplayRevokesIssuedTokens`, `TestAuthorizationCodeReplayRevokesIssuedTokens`                                                    | `TestCompleteReplay`, `TestCompleteConcurrentCallbacks`                                                                | stack: `TestCallbackReplay`, `TestProvenCodeReplayRevokesTheClientsTokens`, `TestConcurrentCallbacksAcrossReplicas`; interop: `TestInteropCodeReplay`; rp: `TestZitadelCallbackReplay`; e2e: `provider_code_flow`; suite: `oidcc-codereuse`, `oidcc-codereuse-30seconds` |
| R23 | Token substitution and confusion (Core §3.1.3.8, RFC 9068 §5, RFC 8725 §3.11)                | `TestCodeExchangeFailures`; jwt: `TestOAuth2AccessTokenSignerFollowsRFC9068`                                                                                   | `TestAccessTokenNotAcceptedAsIDToken`, `TestIDTokenAccessTokenHash`                                                    | stack: `TestTokenResponseSubstitution`, `TestIDTokenUsedAsAnotherToken`; interop: `TestInteropJWTAccessTokenIsNotAnIDToken`                                                         |
| R24 | Fail closed on storage and network failures (RFC 9700 §4.5.3.2)                              | `TestAuthorizationFailsClosedOnServerSideErrors`, `TestCodeExchangeFailures`                                                                                   | `TestDiscoveryHTTP`, `TestTokenResponse`, `TestUserInfoTransport`, `TestBeginSaveFailure`                             | stack: `TestProviderStorageFailuresReachTheClient`, `TestTransactionStoreDownAtTheCallback`, `TestTokenResponseLostAfterCommit`, `TestTokenEndpointTimeout`, `TestDiscoveryOutage` |
| R25 | Login transactions consumed once across instances, integrity against store writers          | —                                                                                                                                                              | `TestMemoryStoreConformance`, `TestStoreWriterCannotForgeIntegrity`, `TestTransactionKeyRotation`                       | stack: `TestConcurrentCallbacksAcrossReplicas`, `TestRealBackendConformance`, `TestRealBackendReplicaRace`, `TestRealBackendCallbackRace`                                          |
| R26 | Login CSRF, open redirect and clickjacking at the applications' pages (RFC 9700 §4.11, §4.16) | example tests (`TestOpenIDProviderRefusals`)                                                                                                                   | example tests (`TestOIDCClientExample`: cross-origin login starts refused)                                             | e2e: `provider_errors`, `browser_cross_site`                                                                                                                                          |

## Explicitly unsupported

Provider — not advertised, and refused with: implicit and hybrid flows
(`unsupported_response_type`); `form_post`, `fragment` and JARM (a bare
`400`); request objects (`request_not_supported`,
`request_uri_not_supported`); the `registration` parameter
(`registration_not_supported`); dynamic registration; pairwise subjects;
encrypted ID Tokens; signed or encrypted UserInfo; aggregated and
distributed claims; session management and every logout specification;
`client_secret_jwt`, `private_key_jwt`, mTLS; EdDSA, HMAC and `none` ID
Tokens; scope claims in the ID Token (UserInfo only).

Client — refused: implicit and hybrid flows, `fragment`, JARM, PAR, request
objects, the `claims` parameter, encrypted and HMAC-signed or unsigned ID
Tokens, signed or encrypted UserInfo (`ErrUserInfoUnsupported`),
`private_key_jwt`, `client_secret_jwt`, mTLS, DPoP. Not provided: a refresh
helper (and so the §12.2 checks of refreshed ID Tokens), logout, dynamic
registration, static metadata, WebFinger, templated multi-tenant issuers,
the UserInfo form-body method, resolution of aggregated and distributed
claims. The conformance-suite runs below show the observable behaviour of
each that a module exercises.

## Independent implementations

| Implementation                                   | Version                       | Plays    | Where                                      | Scenarios                                                                                                                       |
| ------------------------------------------------ | ----------------------------- | -------- | ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------- |
| `github.com/coreos/go-oidc/v3`, `golang.org/x/oauth2` | v3.21.0, v0.37.0          | RP       | `internal/interop/oidcop`                  | code flow (three client authentications), path issuers, refresh and reuse, key rotation, `prompt`, `max_age`, `id_token_hint`, the `claims` parameter, narrowed consent, PS/RS512/ES ID Tokens, code replay, JWT access tokens refused as ID Tokens |
| `github.com/zitadel/oidc/v3` example provider      | v3.51.14                      | OP       | `internal/interop/oidcrp`                  | code flow, every client authentication and response mode, UserInfo, callback replay, `prompt=none`, `max_age`, `acr_values`   |
| Real providers' discovery documents              | captured 2026-10-12T08:24Z    | metadata | `internal/interop/oidcrp/testdata/metadata` | Google, Microsoft Entra, Apple, GitLab, Salesforce, Auth0: `New` per client profile (`TestProviderMetadataCorpus`)              |
| Headless Chrome (chromedp)                       | v0.16.0, Chrome 154           | browser  | `internal/interop/oidcrp`                  | SameSite behaviour of the binding cookie (`TestBrowserBindingCookie`, `OIDC_BROWSER_TESTS=1`)                                   |
| OpenID Foundation conformance suite              | 5.3.2 (`11999aa`)             | OP and RP | `internal/interop/oidcstack/conformance`  | see [the runs](#openid-foundation-conformance-suite)                                                                            |
| Tales and Chrome                                 | v0.1.0-rc.23 (`d50dd8b`), Chrome 154 | browser, HTTP client | `e2e/oidc`                  | see [the end-to-end suites](#end-to-end-suites)                                                                                 |

None of them is a dependency of a production module, and the tests of
`internal/interop/oidcstack` import no third-party OpenID Connect, OAuth 2.0
or JOSE library (`stack: TestDependencyPolicy`), so that its evidence is not
mediated by one; the client's own go-jose is part of the code under test.

## Attacks and failures

`internal/interop/oidcstack` runs `oidc/client` against `oidc/provider`
over HTTP and attacks the pair. Every attack fails with its exact reason:

| Attack                                                                                     | Defense                                                                                   | Tests                                                                                     |
| ------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Mix-up with an attacker provider (RFC 9700 §4.4.1)                                          | distinct redirect URI per connection, transaction binding, RFC 9207 `iss`                 | `TestMixUpWithAnAttackerProvider`; the residual risk without `iss`: `TestMixUpResidualWithoutRFC9207` |
| Mix-up between the issuers of one provider; a code redeemed at another issuer              | `iss` check; the code bound to its issuer                                                 | `TestMixUpBetweenIssuersOfOneProvider`                                                    |
| A client of tenant A used at tenant B                                                      | `oauth2.IssuerBoundClient`: unknown at B, byte-identical to an unknown client             | `TestClientBoundToAnotherIssuer`                                                          |
| Sessions of another realm, end-user or age under `prompt=none`                             | `login_required` that reveals nothing about the session                                    | `TestRefusalsRevealNoSession`                                                             |
| Re-signed ID Tokens (20 variants: claims, `typ`, algorithm confusion, `jku`/`x5u`/`jwk` injection) | Core §3.1.3.7 checklist, keys from the configured `jwks_uri` only (`jku`/`x5u`/`jwk`/`x5c` headers refused, Core §2) | `TestResignedIDTokensAreRefused`                                                          |
| Substituted token response or UserInfo answer; an ID Token used as another token           | `at_hash`, `aud`, `nonce`, `typ`, UserInfo `sub`                                          | `TestTokenResponseSubstitution`, `TestUserInfoSubstitution`, `TestIDTokenUsedAsAnotherToken` |
| Code injection; PKCE downgrade                                                             | browser binding, PKCE verifier; no verifier for a challenge-less code                     | `TestCodeInjectionIsDefeated`, `TestPKCEDowngradeIsRefused`                              |
| Callback and code replay; refresh-token reuse                                              | single consumption; family revocation                                                     | `TestCallbackReplay`, `TestProvenCodeReplayRevokesTheClientsTokens`, `TestRefreshReuseRevokesTheClientsTokens` |
| Concurrent callbacks on several replicas                                                   | atomic consumption: one winner, one token request                                         | `TestConcurrentCallbacksAcrossReplicas`, `TestRealBackendCallbackRace`                    |
| Key rotation, abrupt rotation, withdrawal of a leaked key                                  | bounded key-set cache (see [oidc-client.md](oidc-client.md#provider-keys-and-rotation))  | `TestDocumentedRotationIsInvisibleToTheClient`, `TestAbruptRotationWithinTheRefreshInterval`, `TestKeyWithdrawalWindow`, `TestUnknownKeysTriggerABoundedRefresh` |
| Storage, network and endpoint failures                                                     | fail closed, nothing exposed, the code never retried                                      | `TestProviderStorageFailuresReachTheClient`, `TestTransactionStoreDownAtTheCallback`, `TestTokenResponseLostAfterCommit`, `TestTokenEndpointTimeout`, `TestJWKSOutage`, `TestDiscoveryOutage` |

Each library check these tests rely on was mutated (26 mutants of the
client, the provider and `oauth2`): every mutant is detected.

## End-to-end suites

`e2e/oidc` is a Tales suite (opt-in, `make e2e-oidc`, never in CI) against
the real example binaries: `examples/oidc-provider` at
`http://127.0.0.1:8083` and `examples/oidc-client` at
`http://localhost:9000` — two sites, so the browser applies SameSite to the
relying party's cookies. `e2e/oidc/run.sh` builds and starts them, runs the
provider scenarios (tag `provider`) in parallel against one pair of servers,
then each relying-party and browser file on fresh servers.

- Prerequisites: Go, curl, openssl, Chrome (or `CHROME_PATH`) and Tales
  v0.1.0-rc.23 (`go install
  github.com/tales-testing/tales/cmd/tales@d50dd8bdfae9886996fa280072a698df0c0f24ad`).
- Tags: `provider`, `rp-callback`, `browser-lifecycle`,
  `browser-cross-site`, crossed with `protocol` (specification behaviour)
  and `app-hardening` (the examples' own pages: CSRF, open redirect,
  framing).
- Reuse: the provider scenarios find every endpoint through discovery. Only
  `_config.tales` (URLs, clients, end-user) and four keywords —
  `provision_client`, `provision_user`, `op_sign_in`, `op_consent` — are
  specific to the example: replace them to run the `provider` scenarios
  against another provider.
- `make e2e-oidc-live` (`e2e/oidc-live`) signs in with a real provider
  account in a visible Chrome: `LIVE_OIDC_ISSUER`, `LIVE_OIDC_CLIENT_ID`,
  `LIVE_OIDC_CLIENT_SECRET`, the secret staying in the relying party's
  environment.

Recorded run (2026-10-12, macOS arm64, Chrome 154.0.8037.98, Tales
v0.1.0-rc.23): 21 scenarios, 129 steps, all passed. Run against builds with
a library or example check removed, the suite failed for six of seven
(replay and reuse revocation, RFC 9207 `iss`, the store's binding check,
the relying party's cross-origin protection, the provider's login CSRF
check); the seventh — the provider's `prompt=login` freshness check — is
also enforced by the example application itself.

## OpenID Foundation conformance suite

`make conformance` (`internal/interop/oidcstack/conformance/run.sh`) runs a
local copy of the suite against both modules; it is opt-in and never part
of CI. Prerequisites: Docker with compose v2.24 or later, Go, Python 3,
openssl, curl and a checkout of the suite at commit `11999aad` with its
prebuilt images (`OIDF_SUITE_DIR`, see the script's header).

### Setup

- Suite: version 5.3.2, revision `11999aa`, images pinned by digest in
  `compose.override.yml`; its database in memory, its ports on the loopback
  interface, its nginx serving a certificate of the run's CA for
  `localhost.emobix.co.uk`.
- OP side: `TestConformanceOPHelperProcess` serves `oidc/provider` at
  `https://host.docker.internal:9443` (TLS from the run's CA) under
  `oauth2.Profile20` — the Basic plan sends PKCE in a single module — with
  the root issuer and the path issuer `/tenant-a`, RS256, PS256 and ES256
  keys, static clients `conformance-1` (`client_secret_basic` and
  `client_secret_post`) and `conformance-2`, every standard claim, and a
  headless `Interaction`: no page; the end-user authenticates whenever
  `Request.Check` requires it and consents to what is requested (offline
  access with `prompt=consent` only). Plans run through the suite's
  `scripts/run-test-plan.py` (httpx 0.28.1, pyparsing 3.2.3 and their
  dependencies, pinned by hash in `testdata/requirements.txt`) with
  `testdata/op-config.json.tmpl` and the expectation files.
- RP side: `TestConformanceRPPlans` drives the suite's REST API and, for
  every module, logs in with `oidc/client` (discovery, authorization
  request, callback, UserInfo; two logins with the client's clock moved
  11 s for the key-rotation module), records the suite's result and the
  client's outcome, and compares both with `testdata/rp-expected.json`.
  Without the clock move, the second login fails closed
  (`ErrUnknownSigningKey`): Core §10.1.1 lets a provider sign with a new key
  at once, and the client refetches the key set on an unknown `kid`, but at
  most once per 10 s (see
  [oidc-client.md](oidc-client.md#provider-keys-and-rotation)). CI covers
  that variant with `TestAbruptRotationWithinTheRefreshInterval` rather
  than the suite.

### Results

Run of 2026-10-12 (branch of #86 with the harness, reproduced by its review
at `ce1c2fa`; macOS 26 arm64,
Docker 29.8.1, Go 1.26.5): every module ran to completion as expected.

OP plans:

| Plan (configuration)                                                        | Passed | Review | Warning (expected) | Skipped (expected) | Failed |
| --------------------------------------------------------------------------- | ------ | ------ | ------------------ | ------------------ | ------ |
| `oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]` | 29 | 4 | 1 | 1 | 0 |
| `oidcc-config-certification-test-plan` (root issuer)                         | 1      | 0      | 0                  | 0                  | 0      |
| `oidcc-config-certification-test-plan` (path issuer `/tenant-a`)             | 1      | 0      | 0                  | 0                  | 0      |

- Review: `oidcc-prompt-login` and `oidcc-max-age-1` wait for an image of the
  login page shown again; with no login page (headless interaction) the run
  attaches the suite's callback page, the new authentication being in the
  ID Token's `auth_time`. `oidcc-ensure-registered-redirect-uri` and
  `oidcc-ensure-request-object-with-redirect-uri` attach the provider's own
  error page for an unregistered `redirect_uri` (never redirected).
- Warning: `oidcc-ensure-request-with-acr-values-succeeds`
  (`ValidateIdTokenACRClaimAgainstAcrValuesRequest`): `acr_values` are
  voluntary; the headless interaction performs no step-up and asserts no
  `acr`.
- Skipped: `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported`:
  request objects are not supported (`request_not_supported`).
- Passed, among others: `oidcc-server`, `oidcc-server-client-secret-post`,
  every scope and UserInfo module, `oidcc-prompt-none-*`, `oidcc-max-age-10000`,
  `oidcc-id-token-hint`, `oidcc-claims-essential`, `oidcc-codereuse` and
  `oidcc-codereuse-30seconds` (the first access token revoked),
  `oidcc-refresh-token`, `oidcc-ensure-request-with-valid-pkce-succeeds`,
  `oidcc-discovery-endpoint-verification` for both issuers.

RP plans (suite result / our outcome):

| Plan                                                     | Passed | Other results                                                                                                                                                          |
| -------------------------------------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `oidcc-client-basic-certification-test-plan` (`query`)    | 13     | `oidcc-client-test-idtoken-sig-none`: SKIPPED / `ErrIDTokenAlgorithm`                                                                                                  |
| `oidcc-client-formpost-basic-certification-test-plan`    | 13     | `oidcc-client-test-idtoken-sig-none`: SKIPPED / `ErrIDTokenAlgorithm`                                                                                                  |
| `oidcc-client-config-certification-test-plan`            | 5      | `oidcc-client-test-idtoken-sig-none`: SKIPPED / `ErrIDTokenAlgorithm`                                                                                                  |
| `oidcc-client-test-plan` (`client_secret_basic`)          | 24     | `-idtoken-sig-none` SKIPPED; `-userinfo-bearer-body` FAILED / `ErrUserInfo`; `-discovery-webfinger-acct`, `-discovery-webfinger-url` FAILED; `-distributed-claims` INTERRUPTED |
| `oidcc-client-test-plan` (`client_secret_post`), `oidcc-client-test` | 1 | —                                                                                                                                                                   |
| `oidcc-client-test-plan` (`none`), `oidcc-client-test`     | 0      | INTERRUPTED / `ErrInvalidMetadata`                                                                                                                                     |

- Every negative module was refused with its exact reason: invalid or
  missing claims (`ErrIDTokenIssuer`, `ErrIDTokenAudience`,
  `ErrIDTokenMissingClaim`, `ErrIDTokenNonce`), signatures
  (`ErrIDTokenSignature`, `ErrIDTokenAlgorithm` for HS256,
  `ErrUnknownSigningKey` when several keys match without `kid`), a foreign
  UserInfo `sub` (`ErrUserInfoSubject`), a discovery issuer mismatch
  (`ErrIssuerMismatch`), a signed UserInfo (`ErrUserInfoUnsupported`).
  Both key-rotation modules passed.
- `oidcc-client-test-idtoken-sig-none`: unsigned ID Tokens are refused by
  design; the module accepts that and reports SKIPPED.
- `oidcc-client-test-userinfo-bearer-body`: the client sends the token in
  the `Authorization` header only (RFC 6750 §2.1); the module requires the
  form body.
- `oidcc-client-test-discovery-webfinger-*`: WebFinger is not supported;
  the client is configured with the issuer.
- `oidcc-client-test-distributed-claims`: distributed claims are returned as
  received, never fetched; the module waits for that request and is
  stopped after 30 s.
- `none`: the suite's metadata lists no `code_challenge_methods_supported`,
  and the client refuses a public client without advertised S256 (RFC 9700
  §2.1.1) before any login.
- The discovery modules of the Config plan finish on the discovery (and
  JWK Set) request and fail any later one: the driver stops there.

### Reproduce

```sh
git clone https://gitlab.com/openid/conformance-suite.git
git -C conformance-suite checkout 11999aad
docker compose -f conformance-suite/docker-compose-prebuilt.yml pull
OIDF_SUITE_DIR=$PWD/conformance-suite make conformance
```

Results land in `build/conformance` (`summary.md`, the suite's exports, the
driver's `results.json`); `OIDC_CONFORMANCE_PLANS=op` or `rp` runs one side.

## Live checks

- `OIDC_LIVE_DISCOVERY=1` (`rp: TestLiveDiscovery`) reruns the metadata
  corpus checks against the six live providers. Not run on 2026-10-12: the
  recording machine's firewall blocks Go binaries from the Internet; the
  corpus was captured the same day.
- `make e2e-oidc-live`: needs a client registered at a real provider and a
  person to sign in; not run.

## Release checklist

The release process itself (versions, order, `make release-check`) is in
[releasing.md](releasing.md). Before tagging `oidc/provider` or
`oidc/client`, also check:

1. CI is green (`make sync build test lint`, `make test-backends`): every
   test cited above.
2. `make e2e-oidc` passes: 21 scenarios.
3. `make conformance` exits 0: every OP module ends as listed above (one
   expected warning, one expected skip, four reviews whose images are those
   described under Results — the suite's callback page for
   `oidcc-prompt-login` and `oidcc-max-age-1`, which have no login page to
   show, the provider's error page for the two `redirect_uri` modules),
   every RP module as `testdata/rp-expected.json` pins.
4. When the stores or the provider's key handling changed, the opt-in
   runs too: `OIDC_BROWSER_TESTS=1`, `OIDC_LIVE_DISCOVERY=1` (the real
   stores run in CI, item 1).
5. Add a row below.

A failure in 1 to 3 blocks the tag. A new expected failure, skip or
outcome is a change to review like code: it carries its rationale.

| Date       | Commit    | Suite          | `make e2e-oidc` | `make conformance` |
| ---------- | --------- | -------------- | --------------- | ------------------ |
| 2026-10-12 | `ce1c2fa` | 5.3.2 `11999aa` | 21/21 passed    | as expected        |
