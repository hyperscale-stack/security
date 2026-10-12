// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package samlsp implements the SAML 2.0 Service Provider role of
// SP-initiated Web Browser SSO (Profiles §4.1), for enterprise federation:
// the application sends the browser to an identity provider (IdP) with an
// AuthnRequest (HTTP-Redirect binding) and receives the signed Response at
// its assertion consumer service (ACS, HTTP-POST binding). It is an
// optional module: no other module of the workspace imports it.
//
// # Wiring
//
// The application owns its connections, one per trusted IdP (typically
// one per tenant), and resolves them by ID through a [ConnectionResolver].
// A [Connection] carries its own SP entity ID and ACS URL, the trusted
// [IdentityProvider] (usually imported from administrator-provided metadata
// with [ParseIdentityProviderMetadata]) and an optional NameID format:
//
//	sp, err := samlsp.New(samlsp.Config{
//		Connections:  resolver, // the application's connections
//		Transactions: store,    // shared by every instance
//		ReplayCache:  store,
//		// Optional: sign AuthnRequests (required by IdPs that want them).
//		SigningKey:         key,
//		SigningCertificate: cert,
//	})
//
// and serves, for each connection:
//
//   - its SP metadata, to register at the IdP: [ServiceProvider.ServeMetadata]
//     (or [ServiceProvider.Metadata]);
//   - a login entry point calling [ServiceProvider.BeginLogin] and
//     redirecting the browser to the URL it returns;
//   - its ACS URL, routed to [ServiceProvider.CompleteLogin]; on success the
//     application creates its own session from the returned [Identity].
//
// Transactions and the replay cache MUST be shared by every instance of a
// deployment. The storage/memory package is for development and tests; the
// saml/sp/store/sql and saml/sp/store/redis modules are the production
// stores, and storetest.RunConformance checks any other implementation of
// [Storage].
//
// # Login transactions
//
// BeginLogin stores a transaction (the 256-bit request ID, the connection,
// the options and an opaque AppState) under a random RelayState handle and
// binds it to the browser with a __Host- prefixed cookie: SameSite=None,
// because the IdP's POST to the ACS is cross-site and would not carry a Lax
// or Strict cookie. CompleteLogin accepts a Response only for an unexpired,
// unconsumed transaction of the same browser and connection, whose signed
// SubjectConfirmationData answers its request ID; it consumes the
// transaction atomically (one winner across instances) and records the
// assertion in the replay cache. Unsolicited (IdP-initiated) responses are
// refused, and RelayState is never a URL: the application's return target
// stays server-side in [LoginOptions].AppState (no open redirect).
//
// # Trust policy
//
// Trust comes only from the connection: the IdP entity ID and its signing
// certificates. Nothing in a response, neither its Issuer nor its KeyInfo,
// can extend it. Before any cryptography, a response must pass a lexical
// gate and a structural profile that refuse, rather than interpret,
// anything ambiguous:
//
//   - XML: no DTD, entity or processing instruction; at most
//     [MaxResponseElements] elements and bounded tokens, depth, attributes,
//     namespace declarations and in-scope prefixes; unique attributes and
//     declared prefixes; [Config].MaxResponseSize bytes (256 KiB by
//     default, 1 MiB at most).
//   - Shape: exactly one Assertion, child of the Response, with unique IDs,
//     one Issuer, one Subject with one NameID and one bearer
//     SubjectConfirmation, one AuthnStatement and only understood
//     Conditions; a Response without Issuer, an assertion without NameID or
//     with several of these elements is refused with a typed error, even
//     where the schema would allow it. Encrypted assertions are refused
//     ([ErrEncryptedAssertionUnsupported]).
//   - Signatures: the Response or its Assertion must be signed (errata E93
//     and E26), each signature enveloped in its parent, referencing its ID,
//     with exactly the enveloped-signature and exclusive C14N transforms and
//     no ds:Object. Signature methods RSA or ECDSA with SHA-256/384/512,
//     SHA-256/384/512 digests; SHA-1 only for a connection that sets
//     [Connection].InsecureAllowSHA1; inclusive C14N, HMAC and unknown
//     algorithms never. IdP keys are RSA of 2048 to 8192 bits or ECDSA
//     P-256/384/521, and their certificate validity is enforced.
//
// The signatures are then verified by gosaml2 and goxmldsig, and every value
// used afterwards (identity, times, audiences) comes from the verified
// canonical bytes. The SAML processing rules follow: Destination (required
// when the Response is signed), Issuers, Recipient, InResponseTo, the time
// bounds with [Config].ClockSkew, every AudienceRestriction, ForceAuthn, the
// requested authentication context and the NameID format.
//
// # Identity
//
// An [Identity] is unique within its connection only: a tenant can
// configure an IdP whose entity ID collides with another tenant's. An
// application keys external accounts on the ConnectionID and the
// persistent NameID (with the Issuer and qualifiers); it never keys them on
// a transient NameID or an email attribute, and never links accounts by
// email automatically.
//
// # Errors
//
// Every refusal of a login matches [ErrRejected], which wraps
// security.ErrInvalidCredentials, and a specific sentinel ([ErrAssertionReplayed],
// [ErrInvalidSignature], ...); an IdP error status is a [*StatusError]. Error
// messages never contain the response's content. Store and resolver failures
// are returned as they are and do not match ErrRejected. An application
// answers a rejection with a generic page and HTTP 200: Bindings §3.5.6
// forbids HTTP error statuses for SAML processing failures.
//
// # Dependencies
//
// XML signature verification and canonicalization are never implemented
// here: they come from github.com/russellhaering/gosaml2 v0.12.0 and
// github.com/russellhaering/goxmldsig, required at v1.6.1 or later
// (CVE-2026-33487 signature bypass, GHSA-qhrp-hfff-vphr memory
// amplification). gosaml2 is maintained, verifies what it decodes, and is
// used here only for AuthnRequest encoding and response verification; its
// advisories on Single Logout and decryption concern paths this package
// never reaches. github.com/crewjam/saml was not chosen: it is used only as
// the independent IdP of the interoperability tests. See
// docs/security-considerations.md for the full rationale.
//
// # Not supported
//
// Single Logout, IdP-initiated SSO, bindings other than HTTP-Redirect
// (requests) and HTTP-POST (responses), encrypted assertions, the IdP role,
// verification of signed metadata and network retrieval of metadata.
//
// # Observability
//
// BeginLogin and CompleteLogin record spans under the instrumentation scope
// github.com/hyperscale-stack/security/saml/sp, with the connection, the IdP
// entity ID, the outcome and the reason of a rejection as attributes; see
// docs/observability.md.
package samlsp
