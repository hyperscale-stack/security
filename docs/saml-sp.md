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
| Response | HTTP-POST binding to the connection's ACS URL; with `Connection.ResponseOrigins`, only from the IdP's origins (see [§6](#the-acs-endpoint)) |
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
  one exactly. A `KeyInfo` without certificate (a `KeyName` or `KeyValue`
  only) selects nothing and counts as absent, except on an Assertion whose
  Response is signed (`ErrInvalidSignature`: that signature covers it).
  Without `KeyInfo`, the three most recent valid certificates are tried,
  the one that verified the connection's last such signature first.
- Every value is read from the verified, canonical bytes (gosaml2 and
  goxmldsig), never from the raw document. A comment injected into a
  `NameID` cannot truncate it; the corpus and the Keycloak wrapping tests
  check this on real Apache Santuario output.

| Value | Read from | Must equal |
| --- | --- | --- |
| Response `Issuer` and Assertion `Issuer` (one each, required) | the verified response | the connection's IdP entity ID; the `Format`, if any, is `entity` |
| `Destination` | Response (compared when present, required when the Response is signed) | the connection's ACS URL |
| Received location | the HTTP request: escaped path, `r.Host`, query string | the ACS URL's path and host, without a query string (Core §3.2.2, Bindings §3.5.5.2) |
| `Origin`, or `Referer` without `Origin` | the HTTP request, when `Connection.ResponseOrigins` is set | one of those origins |
| `InResponseTo` | the bearer `SubjectConfirmationData` (required; absent means unsolicited) and, on a Success, the Response (required, Core §3.2.2) | the request ID of the browser's transaction |
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
| refresh interval | `cacheDuration`, or 1 hour when absent | clamped to `[MinRefresh, MaxRefresh]` (5 minutes, 24 hours); an explicit `PT0S` asks for `MinRefresh` |
| early expiry | — | a document whose `validUntil` comes before its scheduled refresh is refreshed once it expires, at most once per `RetryInterval` |
| `RetryInterval` | 1 minute | spacing of the attempts after a failure or an early expiry, whatever the traffic |
| `MaxStale` | 7 days | how long the last good document is served while refreshes fail; never past its `validUntil` |
| afterwards | — | `BeginLogin` and `CompleteLogin` fail closed with `ErrMetadataExpired` |

  A refresh starts at the first use after it is due and runs in the
  background: while a usable document is cached, no login waits for it, so
  a slow or hung metadata endpoint never reaches the login path. Only a
  caller with nothing usable waits. A new key is therefore trusted from the
  first login after the refresh completes.

### 3.5 Single use and replay

- A transaction is consumed atomically, one winner across instances, once
  the response passed the browser binding, the transaction checks, the
  status and the Response `InResponseTo`, and before any signature is
  verified: **a login allows one verification**. A response refused from
  then on ends the login, and any later POST gets `ErrTransactionConsumed`:
  the user starts over. A response refused earlier consumes nothing.
- Only the browser holding the binding cookie gets that far. A page that
  knows a victim's in-flight RelayState handle and request ID (a leaked IdP
  redirect URL) can make her browser post a forged response, which burns
  her login; `Connection.ResponseOrigins` refuses such a POST first (see
  [§5](#5-sessions-and-logout)).
- Each stored transaction carries a MAC under a server-held key
  (`Config.TransactionKeys`) over its ID, browser binding, payload and
  expiry, verified before any stored field is used: an altered record fails
  with `ErrTransactionIntegrity` and consumes nothing.
- The assertion then goes to the replay cache, keyed by a digest of the
  connection, the issuer and the assertion ID (`ErrAssertionReplayed`). The
  Response ID is not a replay key: a re-wrapped assertion is the same
  assertion.
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
| Refused outright | DTDs, entities, processing instructions, two attributes of one local name, prefixed attributes named like SAML or XML-DSig ones, `xml:` attributes other than `xml:lang`, `xml:space`, `xml:base` and `xml:id` |
| Verifications per login | one: the transaction is consumed before the signatures are verified (at most three gosaml2 runs for a signature without `KeyInfo`) |

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
    the attacker's own tenant. `BeginLogin` cannot tell: the victim's
    browser started that login. **The application must start logins only
    from a same-origin user gesture**: a GET whose `Sec-Fetch-Site` is
    `same-origin` or `none` (a link of the site, the address bar), or a POST
    carrying a CSRF token. Refuse `cross-site` and `same-site`.
  - *A leaked in-flight request*: the IdP redirect URL carries the request
    ID and the RelayState handle. Whoever learns it while the login is
    pending (browser history, a proxy log) can sign in at the IdP as
    herself, get the response to the victim's request and auto-post it from
    a page the victim visits: the victim's browser attaches its binding
    cookie and is signed in as the attacker, or, with a forged response,
    loses that login. `Connection.ResponseOrigins` refuses a POST from
    another origin than the IdP's (see [§6](#the-acs-endpoint)); without
    it, keep `TransactionTTL` as short as the IdP interaction allows, never
    log full IdP redirect URLs, and show the signed-in account after a
    login.

  `examples/saml-sp` gates its login this way and also accepts a request
  without `Sec-Fetch-Site`, which browsers older than Fetch Metadata do not
  send. That trade-off keeps those browsers working and leaves them open to
  forced initiation. A strict deployment refuses a missing header too, or
  starts logins with a CSRF-protected POST. The browser suite (BR8) shows
  the example refusing a login forced from another site and from a sibling
  host. It also shows a header-less forced login completing, because the
  library leaves intent to the application.

```go
mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none": // add "" to admit browsers without Fetch Metadata
	default:
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
  unauthenticated users. Rate-limit the ACS per client too: a POST that
  passes the binding check costs one signature verification.

### Transaction keys

- `Config.TransactionKeys` is required: 1 to 4 keys of at least 32 bytes
  from a cryptographic source (`openssl rand -hex 32`), the same on every
  instance, kept in a secret store. `TransactionKeys[0]` protects the
  transactions `BeginLogin` stores; every key is accepted by
  `CompleteLogin` (rotation: [§7](#transaction-keys-1)).
- The keys are the records' only integrity protection. Use keys distinct
  from the OpenID Connect client's and the session's, and replace a leaked
  key at once: the logins in progress then fail once
  (`ErrTransactionIntegrity`).
- The stores remain trusted for availability and single consumption: give
  the SP least-privilege access (a Redis ACL limited to its key prefix, a
  database user limited to its two tables).

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
- Mount `CompleteLogin` at exactly the connection's ACS URL: it refuses a
  request received on another path or host (`r.Host`) or with a query
  string (`ErrDestinationMismatch`, Core §3.2.2).
- `Connection.ResponseOrigins` (optional, at most 8) lists the origins of
  the IdP pages that post the responses, serialized as browsers send them
  in `Origin` (`https://idp.example.com`, a port only when not the
  default). `CompleteLogin` then requires the request's single `Origin`
  header — or, from a browser that sends no `Origin`, its `Referer`'s
  origin — to be one of them, and refuses `null`, two `Origin` headers or
  neither header (`ErrOriginMismatch`), before the transaction is touched.
  It needs an IdP page that lets browsers send its origin: with
  `Referrer-Policy: no-referrer` or `same-origin`, from a sandboxed page or
  after a cross-origin redirect, browsers send `Origin: null`. Keycloak's
  default realm sends `no-referrer` from its POST page; setting the realm's
  Referrer-Policy header to `strict-origin-when-cross-origin` (Realm
  settings → Security defenses → Headers) makes it usable (Keycloak live
  run, K8). In Chrome, the IdP's POST carries the IdP's origin and an
  attacker's auto-post carries the attacker's (browser suite, BR1 and
  BR3).

### Cookies, proxies and hosts

- The binding cookie is `__Host-samlsp`: `Secure`, `HttpOnly`, `Path=/`, no
  `Domain`, `SameSite=None`. TLS termination at a proxy is fine: what
  matters is that the browser sees https. Plain http works only on
  loopback, for development.
- **The login route and the ACS must be on the same host.** A `__Host-`
  cookie is host-only: a login started on `app.example.com` is refused at
  an ACS on `sso.example.com` (`ErrMissingBrowserBinding`, browser suite
  BR6).
- The ACS path and host must reach the application unchanged: a proxy that
  strips a prefix, or rewrites `Host` (nginx's default
  `proxy_set_header Host $proxy_host`), makes every response fail the
  location check (`ErrDestinationMismatch`). Forward the original host
  (`proxy_set_header Host $host;`), or pass `CompleteLogin` a copy of the
  request whose `Host` comes from your trusted proxy's header — only when
  every request passes through that proxy, which overwrites the header (a
  handler must not modify the request it receives):

  ```go
  acs := func(w http.ResponseWriter, r *http.Request) {
  	req := r
  	if host := r.Header.Get("X-Forwarded-Host"); host != "" { // written by our proxy only
  		req = r.Clone(r.Context())
  		req.Host = host
  	}
  	res, err := sp.CompleteLogin(req.Context(), req, connectionID)
  	// ...
  }
  ```

  Behind several proxies `X-Forwarded-Host` may be a comma-separated
  list: take the value your own proxy wrote, never one a client could
  have sent.
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
   (`MaxRefresh` at worst) plus the clock skew. Each instance refreshes on
   its own, at the first use after the refresh is due, in the background,
   so an idle instance learns the key at its first login after that.
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
client's certificate is replaced, and once it is, a request signed by the
previous key gets none (Keycloak case K5). Replace it at the moment the SP
switches, or let Keycloak read the SP metadata URL (not tested here).

### Transaction keys

1. Add the new key last in `Config.TransactionKeys` on every instance.
2. Once every instance runs with it, move it first: new transactions are
   protected by it, the old key still verifies the pending ones.
3. Remove the old key once `TransactionTTL` (10 minutes by default) has
   elapsed. A key removed earlier fails the logins it protected
   (`ErrTransactionIntegrity`), as does a leaked key replaced at once.

`TestCompleteLogin_TransactionKeyRotation` covers these steps.

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
| `ErrTransactionConsumed` | double submission, the back button, a replay; an earlier response of this login was refused after the consumption (one verification per login) | none; the user restarts the login |
| `ErrTransactionIntegrity` | the record was altered in the store; the instances do not share the same `TransactionKeys`; a key was removed before `TransactionTTL` elapsed; logins in progress across the upgrade that introduced the MAC | give every instance the same keys; investigate access to the store |
| `ErrOriginMismatch` | `ResponseOrigins` is set and the IdP page posts with `Origin: null` (`Referrer-Policy: no-referrer`, Keycloak's default) or from another origin; a login CSRF attempt | set `ResponseOrigins` to the origin the IdP page sends, or leave it empty (see [§6](#the-acs-endpoint)) |
| `ErrUnsolicitedResponse` | IdP-initiated SSO; an IdP that drops the RelayState or puts something else than the handle there; a Success Response without `InResponseTo` | start logins at the SP; fix the IdP |
| `ErrInResponseToMismatch` | the response answers another login of the same browser (two tabs) | restart the login |
| `ErrAssertionReplayed` | the same assertion posted twice, or a broken IdP reusing IDs | none |
| `ErrDestinationMismatch`, `ErrRecipientMismatch` | the ACS URL registered at the IdP differs from the connection's; a proxy rewrites the path or the `Host`; the ACS was reached with a query string | align the URLs, character for character; forward the original `Host` |
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
| `ErrMetadataUnavailable`, `ErrInvalidMetadata`, `ErrMetadataExpired` | the metadata URL is unreachable, refused by the outbound policy, or serves another entity; an `EntitiesDescriptor` without a pinned entity ID; refreshes have failed for `MaxStale` | check the URL, `Outbound.AllowedPrefixes` and `RootCAs` for an on-premises IdP; pass the entity ID |
| `ErrInvalidConfig` from `New` or `BeginLogin` | no `TransactionKeys`, or a key under 32 bytes; the IdP wants signed requests and the SP has no key | configure the transaction keys; configure `SigningKey` and `SigningCertificate` |

## 9. Testing your integration

### What runs in CI

| Suite | Where | Covers |
| --- | --- | --- |
| Unit tests | `saml/sp` | every rule, with generated fixtures |
| Pinned adversarial corpus | `saml/sp/testdata/corpus`, `TestCorpus` | 390 entries over 360 signed responses: wrong issuer, audience, destination, recipient and InResponseTo; the received location and the origin of the POST; time windows; statuses; missing fields; untrusted keys and `KeyInfo` without certificate; XSW1–XSW8 and wrapping variants; duplicate IDs; substitution; algorithms; malformed XML; size and decompression limits; parser differentials; records altered in the store. Each entry pins the full refusal message, or the exact identity, and whether the login was consumed. `TestCorpusCoversEveryRule` requires every refusal rule of the sources in some entry |
| crewjam/saml IdP | `internal/interop/saml` | SSO over TLS, metadata exchange both ways, request signatures checked by an independent verifier, IdP and SP key rollover, SHA-1 policy, two IdPs and two connections, cross-tenant substitution, replay, concurrent instances |
| Keycloak replays | `internal/interop/saml/testdata/keycloak-*` | 15 pinned Keycloak responses (14 from 26.7.4, one from 26.0.7); XSW1–XSW8, signature removal, tampering and comment injection applied to the signed 26.7.4 ones |
| Shared stores | `internal/interop/saml` | three SP instances with their own handles on a SQLite file (WAL) and on miniredis and, in the "Store suites (real backends)" job (`make test-backends`), on PostgreSQL 16, MySQL 8.0 (also with `clientFoundRows`, and as a latin1 database under a non-strict `sql_mode`) and Redis 7.4; 16 contenders per race, held at the store until all arrive; the conformance suite, retention over time included |
| Metadata retrieval | `internal/interop/saml` | a `MetadataSource` behind a connection: key rollover, a hung refresh that never delays a login, fetches driven by time only, entity pin, policy refusals |

Regenerate the corpus after a deliberate change with
`go test -run '^TestCorpusGenerate$' -count=1 ./saml/sp -args -corpus.update`
from the repository root. With the Go toolchain recorded in the manifest
(`generatedWith`), regeneration is byte-identical; another Go version
generates other RSA keys and rewrites every file, so regenerate in a commit
of its own. The generator checks every declared outcome first. `TestCorpus`
only replays the pinned files and passes with any toolchain.

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
# append "-args -keycloak.capture" to rewrite testdata/keycloak-26.7.4.
# The 26.0.7 fixture is rewritten only by TestCaptureKeycloakFixture with
# "-args -keycloak.fixture", against a Keycloak 26.0.7.
SAMLSP_KEYCLOAK_URL=http://127.0.0.1:18080 go test -count=1 -run '^TestKeycloakLive$' .

# Shared stores on real servers, which CI runs too (make test-backends);
# MySQL also as a latin1 database under a non-strict sql_mode, which used
# to alter non-ASCII payloads. A backend whose variable is unset is skipped:
SAMLSP_REDIS_ADDR=127.0.0.1:16379 \
SAMLSP_POSTGRES_DSN="postgres://samlsp:$SAMLSP_DB_PASSWORD@127.0.0.1:15432/samlsp?sslmode=disable" \
SAMLSP_MYSQL_DSN="root:$SAMLSP_DB_PASSWORD@tcp(127.0.0.1:13306)/" \
SAMLSP_RACE_ROUNDS=10 go test -count=1 -race -run 'TestSharedStore' .
```

`make e2e-saml` runs the browser suite (`e2e/saml`; `make e2e` runs it,
then `e2e/oidc`): Tales scenarios against the real `examples/saml-sp`
binary in Chrome. It needs Chrome and Tales:

```sh
go install github.com/tales-testing/tales/cmd/tales@d50dd8b   # v0.1.0-rc.23
```

It also needs the ports 8084, 18443 and 18480 free on loopback. A helper
process serves every site (`sp.test`, `acs.sp.test`, `evil.sp.test`,
`idp.test`, `attacker.test`) on one TLS port. Its runtime certificate is
trusted by SPKI hash through Chrome's own flags, so no trust store changes.
CI does not run this suite: re-run it after any change to the example or
to the cookie, login or ACS code of `saml/sp`.

| Scenario | Shows |
| --- | --- |
| BR1, BR2 | the ACS POST is cross-site, carries the IdP's `Origin` and only the `SameSite=None` binding cookie, also with third-party cookies blocked; the redirect after it carries `Lax` cookies, not `Strict` ones |
| BR3 | a valid response auto-posted into another browser is refused and stays usable by its owner; the POST carries the attacker's `Origin` |
| BR4 | a sibling host cannot plant the `__Host-` cookie (`Domain`, nameless and case-variant plants); an unprefixed cookie is planted and ignored |
| BR5 | tampered, swapped, missing and URL RelayStates are refused, consume nothing and never leave the site |
| BR6 | a login started on another host than the ACS fails |
| BR7 | an IdP-initiated response is unsolicited |
| BR8 | the example's `Sec-Fetch-Site` gate refuses a login forced from another site or from a sibling host, and a click on the site still signs in; without Fetch Metadata, a forced login completes |
| BE1 | logout is local: the next login is silent |
| BE2 | twelve hostile return targets never leave the site |

### Interoperability evidence

Recorded on 2026-10-12, re-run on 2026-10-13 after the security audit
fixes:

| Peer | Version | How | Result |
| --- | --- | --- | --- |
| crewjam/saml IdP | v0.5.1 | CI, in process | pass |
| Keycloak (Apache Santuario) | 26.7.4 (`sha256:82a77884…`) | live, K1–K8 | 17/17 subtests pass |
| Chrome | 154.0.8037.98 | Tales v0.1.0-rc.23, `make e2e` | 16 scenarios pass |
| PostgreSQL | 16 (`sha256:ca0bd484…`) | CI (`make test-backends`): conformance suite and races (10 rounds, 16 contenders, race detector) | pass |
| MySQL | 8.0 (`sha256:7dcddc01…`), with and without `clientFoundRows`, and as a latin1 database under `sql_mode=''` | CI (`make test-backends`): conformance suite, races (10 rounds, 16 contenders, race detector) and a non-ASCII `AppState` round trip | pass |
| Redis | 7.4 (`sha256:4fa24486…`), `noeviction` | CI (`make test-backends`): conformance suite and races (10 rounds, 16 contenders, race detector) | pass |

What the Keycloak run established:
- Keycloak applies the client's NameID format only when the AuthnRequest
  asks for it or *Force name ID format* is on. Set
  `Connection.NameIDFormat` to persistent.
- A fresh realm key is refused for `ClockSkew`.
- RSASSA-PSS (`RSA_SHA256_MGF1`) and encrypted assertions are refused.
- `IsPassive` without a session answers `Responder`/`NoPassive`.
- The page carrying its POST form sends the realm's
  `Referrer-Policy: no-referrer` (browsers then post `Origin: null`), and
  `strict-origin-when-cross-origin` once the realm's header is changed
  (K8): see `Connection.ResponseOrigins` in [§6](#the-acs-endpoint).

Known gaps:
- No other live IdP (AD FS, Entra ID, Okta, Shibboleth) was run. Use the
  manual procedure below.
- The browser suite covers Chrome only.

### Against your own IdP

Before going live with an IdP, run `examples/saml-sp` against it:

1. Put the example behind a TLS terminator with a certificate the browser
   trusts, on the host the users will use, and set `SAMLSP_BASE_URL` to its
   https origin. The example listens on `127.0.0.1:8084`; set `SAMLSP_ADDR`
   when the terminator runs elsewhere.
2. Save the IdP's metadata to a file and set `SAMLSP_IDP_METADATA` to it.
   `SAMLSP_TRANSACTION_KEYS` sets the transaction keys (hex, separated by
   commas; a random key for the process when unset), and
   `SAMLSP_RESPONSE_ORIGINS` the IdP origins allowed to post to the ACS
   (see [§6](#the-acs-endpoint)).
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
