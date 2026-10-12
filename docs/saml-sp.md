# SAML Service Provider integration guide

This guide is for applications that sign users in with an enterprise
identity provider through `saml/sp` (package `samlsp`): what the module
supports, the exact trust policy it applies, how to key accounts, how to
deploy and roll keys, how to read its errors, and how it was tested.
The package documentation describes the API.
[security-considerations.md](security-considerations.md#saml-service-provider)
is the threat-model view, and `examples/saml-sp` is a runnable application.

## 1. What this module is, and is not

- **A Service Provider** (SP) for SP-initiated Web Browser SSO (Profiles
  §4.1). The application sends the browser to the IdP with an AuthnRequest
  and receives the signed Response at its assertion consumer service (ACS).
- **Not an identity provider.** It never issues assertions or tokens. An
  application that turns a SAML login into credentials of its own (an
  identity broker, an OpenID provider fronting enterprise IdPs) is a
  relying party here. Such a broker MUST honour the assertion's
  `ProxyRestriction` (Core §2.5.1.6, `Identity.ProxyRestriction`):
  - a `Count` of 0 forbids issuing anything to another party;
  - `Audiences`, when present, lists the only parties it may issue to.
- **Not Single Logout.** Logging out of the application ends the
  application's session only (see [§5](#5-sessions-and-logout)).

## 2. Supported profile

| Feature | Support |
| --- | --- |
| AuthnRequest | HTTP-Redirect binding; signed with `rsa-sha256` when `Config.SigningKey` is set. `BeginLogin` fails with `ErrInvalidConfig` when the IdP's metadata sets `WantAuthnRequestsSigned` and the SP has no key |
| Response | HTTP-POST binding to the connection's ACS URL |
| SP metadata | One document per connection (`Metadata`, `ServeMetadata`): its own entity ID and ACS, `use="signing"` keys only, no encryption key, `AdditionalSigningCertificates` for a rollover |
| IdP metadata | Imported (`ParseIdentityProviderMetadata`), fetched once (`FetchIdentityProviderMetadata`) or kept current (`MetadataSource`); the entity ID is pinned |
| NameID policy | `Connection.NameIDFormat` is requested and enforced (`ErrNameIDFormatMismatch`) unless it is `unspecified` |
| `ForceAuthn` | Requested; a response authenticated before the request is refused (`ErrStaleAuthentication`) |
| `IsPassive` | Requested; the IdP's `NoPassive` status comes back as a `*StatusError` |
| Requested authentication context | `exact` comparison, at most 8 classes; enforced (`ErrAuthnContextMismatch`) |
| Conditions | `NotBefore`/`NotOnOrAfter`, every `AudienceRestriction` (each must name the SP), `OneTimeUse` (single use is enforced anyway), `ProxyRestriction` (surfaced) |
| Session data | `SessionIndex`, `SessionNotOnOrAfter`, `AuthnInstant`, `AuthnContextClassRef`, attributes in document order |

Not supported, each refused with a typed error rather than half-handled:

| Feature | Outcome |
| --- | --- |
| IdP-initiated SSO (unsolicited responses) | `ErrUnsolicitedResponse` |
| Single Logout, Artifact binding, ECP, any binding but those above | Not implemented; anything but a form POST at the ACS is `ErrMalformedRequest` |
| Encrypted assertions, IDs or attributes | `ErrEncryptedAssertionUnsupported`; the SP metadata publishes no encryption key |
| Several assertions, or an assertion out of place | `ErrMalformedResponse` |
| `BaseID` subjects, several `SubjectConfirmation`s or `AuthnStatement`s, unknown conditions | `ErrInvalidAssertion` |
| RSASSA-PSS, SHA-1 without the opt-in, inclusive C14N | `ErrUnsupportedAlgorithm` |
| Signed metadata | The embedded signature is ignored; trust comes from the import (see [§3.4](#34-metadata-trust)) |

## 3. Trust policy

Trust comes from the connection only: the pinned IdP entity ID and its 1 to
8 signing certificates. Nothing in a response extends it.

### 3.1 Signatures, and what is read from where

- The Response, its Assertion or both must be signed (Profiles §4.1.3.5
  and §4.1.4.5, errata E26 and E93). A signed Response covers its single
  assertion and must carry a `Destination`.
- A signature's `KeyInfo` only selects a trusted certificate: it must equal
  one exactly. Without `KeyInfo`, the three most recent valid certificates
  are tried.
- Every value is read from the verified, canonical bytes (gosaml2 and
  goxmldsig), never from the raw document. A comment injected into a
  `NameID` cannot truncate it; the corpus and the Keycloak wrapping tests
  check this on real Apache Santuario output.

| Value | Read from | Must equal |
| --- | --- | --- |
| Response `Issuer` and Assertion `Issuer` (one each, required) | the verified response | the connection's IdP entity ID; the `Format`, if any, is `entity` |
| `Destination` | Response (compared when present, required when the Response is signed) | the connection's ACS URL |
| Request path | the HTTP request | the path of the ACS URL (Bindings §3.5.5.2) |
| `InResponseTo` | the bearer `SubjectConfirmationData` (required; absent means unsolicited) and the Response, when present | the request ID of the browser's transaction |
| `Recipient` | bearer `SubjectConfirmationData` | the connection's ACS URL |
| `Audience` | every `AudienceRestriction` (at least one) | each names the connection's SP entity ID |
| `NameID` | `Subject` (exactly one, never `BaseID`) | its format, when the connection requests one |

### 3.2 Algorithms and keys

| | Accepted |
| --- | --- |
| Signature methods | RSA and ECDSA with SHA-256, SHA-384 or SHA-512; `rsa-sha1` and `ecdsa-sha1` only with `Connection.InsecureAllowSHA1` |
| Digests | SHA-256, SHA-384, SHA-512; SHA-1 only with the opt-in |
| Transforms | exactly enveloped-signature, then exclusive C14N (with or without comments); no `ds:Object` (errata E91) |
| IdP keys | RSA 2048 to 8192 bits, ECDSA P-256, P-384, P-521; ECDSA values in ASN.1 DER (raw `r‖s` fails closed) |
| SP request signing | RSA, `rsa-sha256` |

### 3.3 Time

`ClockSkew` is 3 minutes by default and 5 at most (errata E92). It cannot
be 0: one nanosecond is the strictest setting. With `now` the SP's clock
and `skew` the clock skew:

| Check | Accepted when |
| --- | --- |
| Conditions `NotBefore` | `NotBefore ≤ now + skew` |
| Conditions `NotOnOrAfter` | `now < NotOnOrAfter + skew` |
| Bearer `SubjectConfirmationData NotOnOrAfter` (required) | `now < NotOnOrAfter + skew` |
| Response and Assertion `IssueInstant` | `request start − skew ≤ IssueInstant ≤ now + skew` |
| `AuthnInstant` | `AuthnInstant ≤ now + skew`; with `ForceAuthn`, also `AuthnInstant ≥ request start − skew` |
| `SessionNotOnOrAfter` | `now < SessionNotOnOrAfter + skew` |
| IdP certificate validity | checked at `now − skew`: from `NotBefore + skew` to `NotAfter + skew` |
| Transaction | `now` before the transaction's expiry (`TransactionTTL`, 10 minutes by default, 1 hour at most) |

A certificate whose validity starts when the IdP switches to it is refused
for the first `ClockSkew`: import new certificates ahead of their use. The
Keycloak run hit this with a freshly generated realm key.

### 3.4 Metadata trust

- **Importing is the act of trust.** `ParseIdentityProviderMetadata` reads
  administrator-provided metadata. An embedded signature is not verified,
  and an aggregate is accepted only with a pinned entity ID.
- **Fetching** (`FetchIdentityProviderMetadata`, `MetadataSource`) trusts
  TLS to the configured URL and the pinned entity ID. The URL is
  configuration, never a value read from a request or a SAML message.
  Requests go through the core `outbound` client: public destinations only,
  no redirect, bounded time and size.
- **No response content triggers a fetch.** A response signed by an
  unknown key is refused; it does not refresh the metadata, so an attacker
  cannot make the SP fetch.
- **Refresh and failure** of a `MetadataSource`:

| Setting | Default | Meaning |
| --- | --- | --- |
| refresh interval | `cacheDuration`, or 1 hour | shortened to `validUntil`, clamped to `[MinRefresh, MaxRefresh]` (5 minutes, 24 hours) |
| `RetryInterval` | 1 minute | spacing of the attempts after a failure, whatever the traffic |
| `MaxStale` | 7 days | how long the last good document is served while refreshes fail; never past its `validUntil` |
| afterwards | — | `BeginLogin` and `CompleteLogin` fail closed with `ErrMetadataExpired` |

### 3.5 Single use and replay

- A transaction is consumed atomically by the response that completes it:
  one winner across instances (`ErrTransactionConsumed` for the others). A
  refused response consumes nothing.
- The assertion then goes to the replay cache, keyed by a digest of the
  issuer and the assertion ID (`ErrAssertionReplayed`). The Response ID is
  not a replay key: a re-wrapped assertion is the same assertion.
- Retention is the last instant the assertion could be accepted, plus a
  one-minute margin: `min(SubjectConfirmationData NotOnOrAfter + skew,
  rounded up to the second; transaction expiry) + 1 minute`.
- Purging is per store:
  - `saml/sp/storage/memory` never purges (development and tests only);
  - `saml/sp/store/sql` ships no job, and its package documentation gives
    the cleanup statements;
  - `saml/sp/store/redis` uses key expiry, so Redis must run with
    `noeviction`.

### 3.6 Resource limits

| Limit | Value |
| --- | --- |
| ACS body, or the `SAMLResponse` value of a pre-parsed form | `MaxResponseSize`: 256 KiB by default, 16 KiB to 1 MiB |
| XML document | 1 MiB, 4096 tokens, depth 64 |
| Elements | 450 (`MaxResponseElements`, sized from goxmldsig's canonicalization budget) |
| Per element | 16 attributes, 16 namespace declarations, 32 in-scope prefixes |
| Attribute value | 8 KiB |
| Refused outright | DTDs, entities, processing instructions, two attributes of one local name, prefixed attributes named like SAML or XML-DSig ones |

A response carrying hundreds of group memberships exceeds the element cap
(`ErrResponseTooLarge`). Filter the groups the IdP releases rather than
raising limits.

## 4. Identity mapping

An `Identity` is unique within its connection only. In a multi-tenant
application one tenant can configure an IdP whose entity ID collides with
another tenant's, so the IdP entity ID is a claim of the connection, not a
global name.

**The stable external-identity key** is, for a persistent NameID:

```
(ConnectionID, Issuer, NameQualifier or Issuer, SPNameQualifier or Audience, Format, Value)
```

- `ConnectionID` comes first and is generated by the application, never
  chosen by a tenant.
- An absent `NameQualifier` stands for the issuer, and an absent
  `SPNameQualifier` for the SP entity ID (`Identity.Audience`).
- Values are compared exactly, with no trimming or case folding.
- Encode the key without ambiguity: a connection ID or a value may contain
  any separator. Length-prefix each field, as `accountKey` in
  `examples/saml-sp` does (`<len>:<field>;` for each), or store the SHA-256
  of that encoding.

| NameID format | As a key |
| --- | --- |
| `persistent` | Yes. Configure every IdP to send it (see the per-IdP notes in [security-considerations.md](security-considerations.md#ambiguous-responses-are-refused)) |
| `transient` | Never: valid for one session only (Core §8.3.8) |
| `emailAddress`, `unspecified` | No, unless the operator asserts, for that connection, that the value is immutable and never reassigned. Email addresses are renamed and reassigned |

- **Never link accounts by email automatically.** An IdP vouching for an
  address says nothing about the account another tenant's IdP vouches for.
- **Subject identifier attributes.** The SAML V2.0 Subject Identifier
  Attributes Profile (`urn:oasis:names:tc:SAML:attribute:subject-id`,
  `urn:oasis:names:tc:SAML:attribute:pairwise-id`) is an alternative to a
  persistent NameID, read with `Identity.AttributeValues`. Their values are
  scoped (`value@scope`): check the scope against the scopes this
  connection may assert.
- **Logs.** A persistent NameID is a pseudonymous identifier (Core §8.3.7):
  treat it as personal data. Log the connection ID and a digest rather than
  the raw value where possible.
- **Connection re-creation** gives a new connection ID, so new keys. Migrate
  the old identities explicitly, by connection, never by email.

A broker typically stores the key in a table like this:

```sql
CREATE TABLE external_identity (
    tenant_id   VARCHAR(64)  NOT NULL,
    user_id     VARCHAR(64)  NOT NULL,
    provider    VARCHAR(80)  NOT NULL, -- 'saml:' || connection ID
    subject     VARCHAR(128) NOT NULL, -- hex SHA-256 of the encoded key
    PRIMARY KEY (provider, subject)
);
```

## 5. Sessions and logout

- **The application owns the session.** Create it after `CompleteLogin`
  succeeds, with a fresh session identifier (no fixation). Bound its
  lifetime by `SessionNotOnOrAfter`, as `examples/saml-sp` does.
- **Do not mint a `SameSite=Strict` session at the ACS.** The redirect that
  follows the ACS is still a cross-site navigation: Chrome sends a `Lax`
  cookie set at the ACS with it, but not a `Strict` one (browser suite,
  BR1). The user would appear signed out until the next same-site
  navigation.
- **Local logout is not Single Logout.** The IdP session lives on, and the
  next login is silent, without credentials (browser suite, BE1). Say so in
  the logout UI. Use `ForceAuthn` when the application needs a fresh
  authentication, for example a step-up or a switch of account.
- **Login CSRF has two halves.**
  - *Response injection*: an attacker posts her own valid response into the
    victim's browser. The browser binding refuses it
    (`ErrMissingBrowserBinding` or `ErrBrowserBindingMismatch`), and a
    sibling host cannot plant the `__Host-` cookie (BR3, BR4).
  - *Forced initiation*: an attacker page navigates the victim to the
    login of a connection whose IdP signs her in as the attacker, typically
    the attacker's own tenant. The binding cannot tell: the victim's browser
    started that login. **The application must start logins only from a
    same-origin user gesture**: a POST carrying a CSRF token, or a GET
    whose `Sec-Fetch-Site` is `same-origin` or `none` (the address bar).
    Refuse anything else, including a missing header, or answer with a page
    whose button starts the login. BR8 shows the attack on the ungated
    example and the gate refusing it.

```go
mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "same-origin" && site != "none" {
		http.Error(w, "start the sign-in from this site", http.StatusForbidden)
		return
	}
	// ... BeginLogin and redirect, as in examples/saml-sp
})
```

## 6. Deployment

### Several instances

- `Transactions` and `ReplayCache` must be shared by every instance and
  read from the primary:
  - `saml/sp/store/sql` on PostgreSQL, MySQL (with or without
    `clientFoundRows`) or SQLite;
  - `saml/sp/store/redis`, with `noeviction`.

  Both are raced across instances in the test suites (see
  [§9](#9-testing-your-integration)).
- Keep the instances' clocks synchronized well within the one-minute
  replay margin and the clock skew.
- Rate-limit the login entry point: `BeginLogin` writes to the store for
  unauthenticated users.

### Connections

- One connection per trusted IdP, typically per tenant, each with its own
  SP entity ID and ACS URL. Two connections trusting one IdP must not share
  them: the per-connection SP identity is what keeps one tenant's responses
  out of the other's connection.
- Configure absolute URLs. Never derive them from `Host` or
  `X-Forwarded-*` headers.
- The `ConnectionResolver` runs on every login and every ACS request. Cache
  it, and invalidate the cache when a connection changes. With a
  `MetadataSource`, call `IdentityProvider(ctx)` in the resolver.

### The ACS endpoint

- Exempt it from the application's CSRF protection: the POST comes from the
  IdP's page. The browser binding and `InResponseTo` are its CSRF defense.
- Do not let a middleware parse its form first. `CompleteLogin` bounds the
  `SAMLResponse` value either way, but Go's own form limit is 10 MB. Any
  body limit in front of it must be at least `MaxResponseSize`.
- Answer every refusal with one generic page and HTTP 200 (Bindings
  §3.5.6), and log the error. Never show the reason or the IdP's
  `StatusMessage`: both are attacker-influenced.

### Cookies, proxies and hosts

- The binding cookie is `__Host-samlsp`: `Secure`, `HttpOnly`, `Path=/`, no
  `Domain`, `SameSite=None`. TLS termination at a proxy is fine: what
  matters is that the browser sees https. Plain http works only on
  loopback, for development.
- **The login route and the ACS must be on the same host.** A `__Host-`
  cookie is host-only: a login started on `app.example.com` is refused at
  an ACS on `sso.example.com` (`ErrMissingBrowserBinding`, browser suite
  BR6).
- The ACS path must reach the application unchanged: a proxy that strips a
  prefix makes every response fail the path check
  (`ErrDestinationMismatch`).
- Browsers that mishandle `SameSite=None` (Safari on iOS 12 and macOS
  10.14, Chrome 51–66) cannot complete a login. Blocking third-party
  cookies did not break the login in Chrome (BR2): the ACS POST is a
  top-level navigation, not a third-party request.

### Return targets

The library never redirects: `LoginOptions.AppState` comes back from
`CompleteLogin`. An application redirecting to it must accept local paths
only, with an allowlist rather than a cleanup:
- one leading `/` and no `//`;
- RFC 3986 path and query characters only: no control character, white
  space, `\` or non-ASCII byte;
- still a local path once percent-decoded.

Browsers drop TAB, LF and CR inside URLs and read `\` as `/`, so
`/<TAB>/evil.example` leaves the site. `safeReturn` in `examples/saml-sp`
implements this rule. The browser suite (BE2) plays twelve hostile targets
against it. Against a check that only refused `//`, `\`, CR and LF, the
TAB payload lands on the attacker's site.

## 7. Rollover runbooks

### IdP signing key

1. The IdP publishes the new certificate next to the current one (errata
   E68: any listed key may sign).
2. The SP learns it. With imported metadata, re-import the document on
   every instance. With a `MetadataSource`, wait one refresh interval
   (`MaxRefresh` at worst) plus the clock skew: each instance refreshes on
   its own.
3. The IdP switches to the new key. The certificate in its `KeyInfo` must
   equal the imported one exactly, and it is accepted only from its
   `NotBefore + ClockSkew`.
4. The IdP retires the old certificate. Responses it signs are refused once
   every instance has re-imported or refreshed.

`TestMetadataSourceFollowsKeyRollover`, `TestIdPKeyRollover` and the
Keycloak case K4 cover these steps.

### SP signing key (AuthnRequest signatures)

1. Announce: set `AdditionalSigningCertificates` to the new certificate.
   The SP metadata lists both, `use="signing"`. Every IdP re-imports or
   refreshes the SP metadata.
2. Switch: the new key becomes `SigningKey`, and the old certificate may
   stay in `AdditionalSigningCertificates` for a while.
3. Retire: drop the old certificate from the metadata.

**Keycloak** keeps one SP signing certificate per SAML client, so step 1
does not apply. A request signed by the new key gets no response until the
client's certificate is replaced (Keycloak case K5). Replace it at the
moment the SP switches, or let Keycloak read the SP metadata URL (not
tested here).

### Changing or deleting a connection

In-flight logins of a deleted connection fail closed (`ErrUnknownConnection`),
and a transaction is never completed by another connection
(`ErrTransactionMismatch`). Identities are keyed by the connection ID: plan
their migration before re-creating a connection.

## 8. Troubleshooting

Every refusal matches `ErrRejected` (which wraps
`security.ErrInvalidCredentials`) and one specific sentinel. Store and
resolver failures are returned as they are and do not match `ErrRejected`.

| Error | Typical cause | Action |
| --- | --- | --- |
| `ErrMissingBrowserBinding` | the login started on another host than the ACS; the browser drops `SameSite=None` cookies; cookies are blocked for the site; a response posted from another browser | serve the login and the ACS from one host; check the browser; nothing to do for an attack |
| `ErrBrowserBindingMismatch` | the response belongs to a login of another browser (login CSRF attempt) | none: expected under attack |
| `ErrTransactionNotFound` | the RelayState was replaced by another handle; the transaction store is not shared by every instance; the transaction was purged | share the store; check that the IdP returns the RelayState unchanged |
| `ErrTransactionExpired` | the user took longer than `TransactionTTL` at the IdP | restart the login; raise `TransactionTTL` (1 hour at most) if this is common |
| `ErrTransactionConsumed` | double submission, the back button, a replay | none |
| `ErrUnsolicitedResponse` | IdP-initiated SSO; an IdP that drops the RelayState or puts something else than the handle there | start logins at the SP; fix the IdP |
| `ErrInResponseToMismatch` | the response answers another login of the same browser (two tabs) | restart the login |
| `ErrAssertionReplayed` | the same assertion posted twice, or a broken IdP reusing IDs | none |
| `ErrDestinationMismatch`, `ErrRecipientMismatch` | the ACS URL registered at the IdP differs from the connection's; a proxy rewrites the path | align the URLs, character for character |
| `ErrAudienceMismatch` | the SP entity ID registered at the IdP differs | align the entity ID |
| `ErrIssuerMismatch` | wrong IdP entity ID in the connection | re-import the IdP metadata |
| `ErrInvalidSignature` | the IdP signs with a key not imported yet (rollover); an unsigned response; tampering | import the IdP's current metadata; enable signing at the IdP |
| `ErrUnsupportedAlgorithm` | SHA-1, RSASSA-PSS or inclusive C14N at the IdP | configure RSA-SHA256 and exclusive C14N; `InsecureAllowSHA1` only for a legacy IdP |
| `ErrEncryptedAssertionUnsupported` | the IdP encrypts assertions | disable assertion encryption for this SP at the IdP |
| `ErrAssertionExpired`, `ErrAssertionNotYetValid` | clock drift between IdP and SP beyond `ClockSkew`; a slow user; a session already ended | synchronize the clocks (NTP) |
| `ErrStaleAuthentication` | `ForceAuthn` requested, but the IdP reused its session | fix the IdP, or accept no `ForceAuthn` |
| `ErrNameIDFormatMismatch` | the IdP sends another NameID format than the connection requests | configure the IdP (persistent) |
| `ErrAuthnContextMismatch` | the IdP authenticated with another context class | align the requested classes |
| `ErrResponseTooLarge` | too many attributes or groups; an oversized body | filter what the IdP releases |
| `ErrMalformedResponse`, `ErrInvalidAssertion`, `ErrMalformedRequest` | a response shape the SP refuses (several assertions, an unknown condition, a non-POST request) | configure the IdP to send one assertion with a persistent NameID |
| `*StatusError` (`ErrResponseStatus`) | the IdP refused: `NoPassive` (an `IsPassive` login without a session), `AuthnFailed`, `RequestDenied`, `InvalidNameIDPolicy` | per status; its `AppState` and `ConnectionID` identify the login |
| `ErrMetadataUnavailable`, `ErrInvalidMetadata`, `ErrMetadataExpired` | the metadata URL is unreachable, refused by the outbound policy, or serves another entity; refreshes have failed for `MaxStale` | check the URL, `Outbound.AllowedPrefixes` and `RootCAs` for an on-premises IdP |
| `ErrInvalidConfig` from `BeginLogin` | the IdP wants signed requests and the SP has no key | configure `SigningKey` and `SigningCertificate` |

## 9. Testing your integration

### What runs in CI

| Suite | Where | Covers |
| --- | --- | --- |
| Unit tests | `saml/sp` | every rule, with generated fixtures |
| Pinned adversarial corpus | `saml/sp/testdata/corpus`, `TestCorpus` | 314 signed responses: wrong issuer, audience, destination, recipient and InResponseTo; time windows; statuses; missing fields; untrusted keys; XSW1–XSW8 and wrapping variants; duplicate IDs; substitution; algorithms; malformed XML; size and decompression limits; parser differentials. Each entry pins the full refusal message, or the exact identity. `TestCorpusCoversEveryRule` requires every refusal rule of the sources in some entry |
| crewjam/saml IdP | `internal/interop/saml` | SSO over TLS, metadata exchange both ways, request signatures checked by an independent verifier, IdP and SP key rollover, SHA-1 policy, two IdPs and two connections, cross-tenant substitution, replay, concurrent instances |
| Keycloak replays | `internal/interop/saml/testdata/keycloak-*` | 15 pinned Keycloak responses (14 from 26.7.4, one from 26.0.7); XSW1–XSW8, signature removal, tampering and comment injection applied to the signed 26.7.4 ones |
| Shared stores | `internal/interop/saml` | three SP instances with their own handles on a SQLite file (WAL) and on miniredis; 16 contenders per race, held at the store until all arrive |
| Metadata retrieval | `internal/interop/saml` | a `MetadataSource` behind a connection: key rollover, fetches driven by time only, entity pin, policy refusals |

Regenerate the corpus after a deliberate change with
`go test -run '^TestCorpusGenerate$' -count=1 ./saml/sp -args -corpus.update`
from the repository root. Regeneration is byte-identical, and the generator
checks every declared outcome first.

### Opt-in suites

`internal/interop/saml/compose.yaml` starts Keycloak, PostgreSQL, MySQL and
Redis, each pinned by digest, on non-default loopback ports. It takes the
passwords from the environment and persists nothing:

```sh
export SAMLSP_KEYCLOAK_ADMIN_PASSWORD="$(openssl rand -hex 16)"
export SAMLSP_DB_PASSWORD="$(openssl rand -hex 16)"
docker compose -f internal/interop/saml/compose.yaml up -d --wait
cd internal/interop/saml

# Keycloak live (each run creates and deletes a realm with a random user);
# append "-args -keycloak.capture" to rewrite testdata/keycloak-26.7.4:
SAMLSP_KEYCLOAK_URL=http://127.0.0.1:18080 go test -count=1 -run '^TestKeycloakLive$' .

# Shared stores on real servers:
SAMLSP_REDIS_ADDR=127.0.0.1:16379 \
SAMLSP_POSTGRES_DSN="postgres://samlsp:$SAMLSP_DB_PASSWORD@127.0.0.1:15432/samlsp?sslmode=disable" \
SAMLSP_MYSQL_DSN="root:$SAMLSP_DB_PASSWORD@tcp(127.0.0.1:13306)/" \
SAMLSP_RACE_ROUNDS=10 go test -count=1 -race -run 'TestSharedStore' .
```

`make e2e` runs the browser suite (`e2e/saml`): Tales scenarios against
the real `examples/saml-sp` binary in Chrome. It needs Chrome and Tales:

```sh
go install github.com/tales-testing/tales/cmd/tales@d50dd8b   # v0.1.0-rc.23
```

It also needs the ports 8084, 18443 and 18480 free on loopback. A helper
process serves every site (`sp.test`, `acs.sp.test`, `evil.sp.test`,
`idp.test`, `attacker.test`) on one TLS port. Its runtime certificate is
trusted by SPKI hash through Chrome's own flags, so no trust store changes.

| Scenario | Shows |
| --- | --- |
| BR1, BR2 | the ACS POST is cross-site and carries only the `SameSite=None` binding cookie, also with third-party cookies blocked; the redirect after it carries `Lax` cookies, not `Strict` ones |
| BR3 | a valid response auto-posted into another browser is refused and stays usable by its owner |
| BR4 | a sibling host cannot plant the `__Host-` cookie (`Domain`, nameless and case-variant plants); an unprefixed cookie is planted and ignored |
| BR5 | tampered, swapped, missing and URL RelayStates are refused, consume nothing and never leave the site |
| BR6 | a login started on another host than the ACS fails |
| BR7 | an IdP-initiated response is unsolicited |
| BR8 | a forced login initiation succeeds without a gate, and the `Sec-Fetch-Site` gate refuses it |
| BE1 | logout is local: the next login is silent |
| BE2 | twelve hostile return targets never leave the site |

### Interoperability evidence

Recorded on 2026-10-12:

| Peer | Version | How | Result |
| --- | --- | --- | --- |
| crewjam/saml IdP | v0.5.1 | CI, in process | pass |
| Keycloak (Apache Santuario) | 26.7.4 (`sha256:82a77884…`) | live, K1–K7 | 16/16 subtests pass |
| Chrome | 154.0.8037.98 | Tales v0.1.0-rc.23, `make e2e` | 15 scenarios, 111 steps pass |
| PostgreSQL | 16 (`sha256:ca0bd484…`) | conformance suite and races (10 rounds, 16 contenders) | pass |
| MySQL | 8.0 (`sha256:7dcddc01…`), with and without `clientFoundRows` | conformance suite and races (10 rounds, 16 contenders) | pass |
| Redis | 7.4 (`sha256:4fa24486…`), `noeviction` | conformance suite and races (10 rounds, 16 contenders) | pass |

What the Keycloak run established:
- Keycloak applies the client's NameID format only when the AuthnRequest
  asks for it or *Force name ID format* is on. Set
  `Connection.NameIDFormat` to persistent.
- A fresh realm key is refused for `ClockSkew`.
- RSASSA-PSS (`RSA_SHA256_MGF1`) and encrypted assertions are refused.
- `IsPassive` without a session answers `Responder`/`NoPassive`.

Known gaps:
- No other live IdP (AD FS, Entra ID, Okta, Shibboleth) was run. Use the
  manual procedure below.
- The browser suite covers Chrome only.

### Against your own IdP

Before going live with an IdP, run `examples/saml-sp` against it:

1. Put the example behind a TLS terminator with a certificate the browser
   trusts, on the host the users will use, and set `SAMLSP_BASE_URL` to its
   https origin.
2. Save the IdP's metadata to a file and set `SAMLSP_IDP_METADATA` to it.
3. Register `<base>/saml/corp/metadata` at the IdP, then sign in from the
   home page.
4. Check:
   - the login succeeds. The example requests a persistent NameID and logs
     any refusal with its sentinel (see [§8](#8-troubleshooting)): a wrong
     format, an unsigned or SHA-1 response, encryption, clock drift or too
     many attributes;
   - the NameID shown is the same at every login, and is not an email;
   - the mail attribute appears when the IdP releases
     `urn:oid:0.9.2342.19200300.100.1.3`;
   - a logout followed by a login is silent (local logout).
5. Remove the registration when done. The example keeps everything in
   memory and writes nothing.
