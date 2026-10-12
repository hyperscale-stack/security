// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/hyperscale-stack/security"
)

// ErrRejected is matched (errors.Is) by every refusal of a SAML login: a
// malformed or oversized message, a correlation failure (transaction,
// browser binding, connection) or a trust failure (signature, issuer,
// audience, time window, replay). It wraps [security.ErrInvalidCredentials]
// so transport mappers classify it like any other invalid credential.
// Infrastructure failures (a store or a resolver returning an error) never
// match it: they are server-side errors, not rejections.
//
// Applications SHOULD render a generic "sign-in failed" page for any
// ErrRejected: Bindings §3.5.6 forbids signaling SAML processing failures
// with HTTP error status codes, and the specific reason is for logs only.
var ErrRejected = fmt.Errorf("samlsp: SAML login rejected: %w", security.ErrInvalidCredentials)

// newRejection builds a sentinel that also matches [ErrRejected].
func newRejection(msg string) error {
	return fmt.Errorf("samlsp: %s: %w", msg, ErrRejected)
}

// Configuration and setup errors. They do not match [ErrRejected], except
// when [ServiceProvider.CompleteLogin] meets them: the connection of a
// transaction vanished or its metadata expired between the two legs, which
// rejects the login.
var (
	// ErrInvalidConfig reports an invalid [Config], or a configuration that
	// cannot serve a request (an IdP that wants signed AuthnRequests while the
	// SP has no signing key).
	ErrInvalidConfig = errors.New("samlsp: invalid configuration")

	// ErrInvalidConnection reports a [Connection] or [IdentityProvider] that
	// fails validation (URLs, entity IDs, key policy).
	ErrInvalidConnection = errors.New("samlsp: invalid connection")

	// ErrInvalidLoginOptions reports [LoginOptions] out of bounds.
	ErrInvalidLoginOptions = errors.New("samlsp: invalid login options")

	// ErrUnknownConnection is returned by a [ConnectionResolver] for an
	// unknown connection ID.
	ErrUnknownConnection = errors.New("samlsp: unknown connection")

	// ErrInvalidMetadata reports IdP metadata that cannot be trusted as
	// configuration (malformed, ambiguous, missing endpoint or key, weak key).
	ErrInvalidMetadata = errors.New("samlsp: invalid identity provider metadata")

	// ErrMetadataExpired reports IdP metadata past its validUntil: Metadata
	// §4.3.2 (errata E94) forbids using invalid metadata.
	ErrMetadataExpired = errors.New("samlsp: identity provider metadata expired")

	// ErrMetadataUnavailable reports IdP metadata that could not be
	// retrieved: a request refused by the outbound policy (the outbound
	// errors stay matchable), a network failure, or an HTTP status other
	// than 200.
	ErrMetadataUnavailable = errors.New("samlsp: identity provider metadata unavailable")
)

// Store contract errors. ErrTransactionExists and ErrInvalidStoreRecord are
// plain errors; the others match [ErrRejected] because they refuse a login.
var (
	// ErrTransactionExists is returned by [TransactionStore.SaveTransaction]
	// when a record with the same ID already exists. It never overwrites.
	ErrTransactionExists = errors.New("samlsp: transaction already exists")

	// ErrInvalidStoreRecord is returned by stores, before any I/O, for a
	// record or key that fails [TransactionRecord.Validate] or
	// [ValidateStoreKey].
	ErrInvalidStoreRecord = errors.New("samlsp: invalid store record")

	// ErrTransactionNotFound reports a RelayState handle with no transaction
	// for the connection: never issued, issued for another connection, or
	// already purged after expiry.
	ErrTransactionNotFound = newRejection("transaction not found")

	// ErrTransactionConsumed reports a transaction that already completed:
	// a replayed or concurrent duplicate response.
	ErrTransactionConsumed = newRejection("transaction already consumed")

	// ErrBrowserBindingMismatch reports a response presented by a browser
	// other than the one that started the transaction. The transaction is
	// not consumed.
	ErrBrowserBindingMismatch = newRejection("browser binding mismatch")

	// ErrAssertionReplayed reports an assertion ID already consumed for its
	// issuer (Profiles §4.1.4.5).
	ErrAssertionReplayed = newRejection("assertion replayed")
)

// Rejections of [ServiceProvider.CompleteLogin]; every one matches
// [ErrRejected].
var (
	// ErrMalformedRequest reports an ACS request that is not an HTTP-POST
	// binding message (Bindings §3.5.4): wrong method or content type,
	// missing or repeated SAMLResponse/RelayState.
	ErrMalformedRequest = newRejection("malformed assertion consumer service request")

	// ErrResponseTooLarge reports a message over a resource limit: request
	// body, decoded size, element/token/attribute/namespace counts, depth,
	// attribute value length, or the verifier's traversal budget.
	ErrResponseTooLarge = newRejection("response exceeds a resource limit")

	// ErrUnsolicitedResponse reports a response not correlated to an
	// SP-initiated request: no RelayState handle, a Success Response without
	// InResponseTo (Core §3.2.2), or no InResponseTo in the bearer
	// SubjectConfirmationData. IdP-initiated SSO is not supported (Profiles
	// §4.1.5, errata E90).
	ErrUnsolicitedResponse = newRejection("unsolicited response")

	// ErrMissingBrowserBinding reports an ACS request without the
	// browser-binding cookie: blocked cookie, another browser, a browser
	// treating SameSite=None as Strict, or a deployment over plain http.
	ErrMissingBrowserBinding = newRejection("missing browser binding cookie")

	// ErrTransactionExpired reports a transaction past its expiry.
	ErrTransactionExpired = newRejection("transaction expired")

	// ErrTransactionMismatch reports a transaction that does not belong to
	// the connection, or whose connection changed (SP entity ID, ACS or IdP
	// entity ID) since the login started.
	ErrTransactionMismatch = newRejection("transaction does not match the connection")

	// ErrMalformedResponse reports a SAMLResponse that is not acceptable
	// XML or not a well-formed SAML Response for this profile: base64,
	// DOCTYPE/entities, processing instructions, namespace or attribute
	// misuse, duplicate IDs, wrong root, assertion count or placement,
	// non-UTC time values, unsupported version.
	ErrMalformedResponse = newRejection("malformed SAML response")

	// ErrEncryptedAssertionUnsupported reports encrypted content
	// (EncryptedAssertion, EncryptedID, EncryptedAttribute, xenc elements).
	// Encryption is not supported; SP metadata publishes no encryption key.
	ErrEncryptedAssertionUnsupported = newRejection("encrypted assertions are not supported")

	// ErrUnsupportedAlgorithm reports a signature, digest or
	// canonicalization algorithm outside the policy (SHA-1 unless the
	// connection opted in, inclusive C14N, HMAC, unknown).
	ErrUnsupportedAlgorithm = newRejection("unsupported signature algorithm")

	// ErrInvalidSignature reports a missing, malformed, misplaced, untrusted
	// or invalid XML signature.
	ErrInvalidSignature = newRejection("invalid signature")

	// ErrResponseStatus reports a non-Success top-level status; the details
	// are in a [*StatusError].
	ErrResponseStatus = newRejection("identity provider returned an error status")

	// ErrIssuerMismatch reports a Response or Assertion Issuer other than
	// the connection's IdP entity ID, or with a non-entity Format.
	ErrIssuerMismatch = newRejection("issuer mismatch")

	// ErrDestinationMismatch reports a Destination other than the
	// connection's ACS URL, a signed Response without Destination, or an ACS
	// request received elsewhere than at that URL: another path, another
	// host (the request's Host), or with a query string (Core §3.2.2,
	// Bindings §3.5.5.2).
	ErrDestinationMismatch = newRejection("destination mismatch")

	// ErrRecipientMismatch reports a bearer SubjectConfirmationData
	// Recipient other than the connection's ACS URL.
	ErrRecipientMismatch = newRejection("recipient mismatch")

	// ErrAudienceMismatch reports a missing AudienceRestriction or one that
	// does not include the connection's SP entity ID.
	ErrAudienceMismatch = newRejection("audience mismatch")

	// ErrInResponseToMismatch reports an InResponseTo other than the ID of
	// the transaction's AuthnRequest.
	ErrInResponseToMismatch = newRejection("InResponseTo mismatch")

	// ErrAssertionExpired reports an assertion, subject confirmation or
	// session past its validity, beyond the clock skew.
	ErrAssertionExpired = newRejection("assertion expired")

	// ErrAssertionNotYetValid reports an assertion whose validity starts
	// in the future beyond the clock skew, or a future instant.
	ErrAssertionNotYetValid = newRejection("assertion not yet valid")

	// ErrInvalidAssertion reports an assertion that violates the Web Browser
	// SSO profile or this package's strict shape (missing or repeated
	// Subject, NameID, SubjectConfirmation, AuthnStatement; non-bearer
	// confirmation; unknown condition).
	ErrInvalidAssertion = newRejection("invalid assertion")

	// ErrNameIDFormatMismatch reports a NameID whose Format differs from the
	// format the connection requested (Core §3.4.1.1).
	ErrNameIDFormatMismatch = newRejection("NameID format mismatch")

	// ErrAuthnContextMismatch reports an AuthnContextClassRef outside the
	// requested classes (Core §3.3.2.2.1, exact comparison).
	ErrAuthnContextMismatch = newRejection("authentication context mismatch")

	// ErrStaleAuthentication reports an AuthnInstant older than the request
	// although ForceAuthn was requested (Core §3.4.1).
	ErrStaleAuthentication = newRejection("stale authentication despite ForceAuthn")
)

// StatusError reports a Response whose top-level StatusCode is not Success
// (Core §3.2.2.2, errata E65). It is only returned once the response was
// correlated to the browser's transaction (RelayState, binding cookie,
// expiry, and InResponseTo when present); nothing is consumed.
//
// Code, SubCode and Message come from a message that may be unsigned: they
// are diagnostics, never authenticated. Code and SubCode keep visible ASCII
// only; Message loses its control, Unicode format (bidi, zero-width) and
// line or paragraph separator characters; each value is capped at 256
// bytes. Message MUST NOT be rendered to end users. A Success code is never
// reported here: a code that is Success only once sanitized is refused as
// ErrMalformedResponse. ConnectionID and AppState come from the server-side transaction, so
// the application can send the user back where the login started.
//
// errors.Is(err, ErrResponseStatus) and errors.Is(err, ErrRejected) hold.
type StatusError struct {
	// Code is the top-level status code URI.
	Code string
	// SubCode is the second-level status code URI, if any.
	SubCode string
	// Message is the StatusMessage text, if any.
	Message string
	// ConnectionID is the connection of the transaction.
	ConnectionID string
	// AppState is the transaction's [LoginOptions.AppState].
	AppState string
}

// Error implements error. It names the SAML 2.0 status codes (Core
// §3.2.2.2) by their short names and any other code as "non-standard
// status": the codes may come from an attacker, so their text is never
// printed (code review F5). Message is omitted.
func (e *StatusError) Error() string {
	if e.SubCode != "" {
		return ErrResponseStatus.Error() + " (" + statusName(e.Code) + ", " + statusName(e.SubCode) + ")"
	}

	return ErrResponseStatus.Error() + " (" + statusName(e.Code) + ")"
}

// statusCodePrefix is the namespace of the SAML 2.0 status codes.
const statusCodePrefix = "urn:oasis:names:tc:SAML:2.0:status:"

// statusNames are the SAML 2.0 status codes (Core §3.2.2.2).
var statusNames = map[string]bool{
	"Success": true, "Requester": true, "Responder": true, "VersionMismatch": true,
	"AuthnFailed": true, "InvalidAttrNameOrValue": true, "InvalidNameIDPolicy": true, "NoAuthnContext": true,
	"NoAvailableIDP": true, "NoPassive": true, "NoSupportedIDP": true, "PartialLogout": true,
	"ProxyCountExceeded": true, "RequestDenied": true, "RequestUnsupported": true,
	"RequestVersionDeprecated": true, "RequestVersionTooHigh": true, "RequestVersionTooLow": true,
	"ResourceNotRecognized": true, "TooManyResponses": true, "UnknownAttrProfile": true,
	"UnknownPrincipal": true, "UnsupportedBinding": true,
}

// statusName returns the short name of a SAML 2.0 status code.
func statusName(code string) string {
	if name, ok := strings.CutPrefix(code, statusCodePrefix); ok && statusNames[name] {
		return name
	}

	return "non-standard status"
}

// Unwrap returns [ErrResponseStatus].
func (e *StatusError) Unwrap() error { return ErrResponseStatus }

// rejection is the error returned for a refused login: its message is the
// static text of its reason (never attacker-controlled content, so it is
// safe to log), while the reason sentinel, ErrRejected and the optional
// underlying cause stay reachable through errors.Is / errors.As.
type rejection struct {
	reason error
	detail string
	cause  error
}

// reject wraps reason (a sentinel) with a static detail and an optional
// cause whose text is never printed.
func reject(reason error, detail string, cause error) error {
	return &rejection{reason: reason, detail: detail, cause: cause}
}

func (e *rejection) Error() string {
	if e.detail == "" {
		return e.reason.Error()
	}

	return e.reason.Error() + " (" + e.detail + ")"
}

func (e *rejection) Unwrap() []error {
	if e.cause == nil {
		return []error{ErrRejected, e.reason}
	}

	return []error{ErrRejected, e.reason, e.cause}
}

// maxDiagnosticLen caps diagnostic strings copied from untrusted messages.
const maxDiagnosticLen = 256

// sanitizeDiagnostic keeps printable characters only and caps the length:
// control characters (no log injection), Unicode format characters (bidi
// overrides and isolates, zero-width characters, soft hyphen, byte order
// mark) and the line and paragraph separators are stripped, so the text
// cannot spoof a log line or reorder what is displayed (Unicode TR #36
// §2). Letters of every script are kept.
func sanitizeDiagnostic(s string) string {
	var b strings.Builder

	for _, r := range s {
		if unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) {
			continue
		}

		if b.Len()+len(string(r)) > maxDiagnosticLen {
			break
		}

		b.WriteRune(r)
	}

	return b.String()
}

// sanitizeURI keeps the visible ASCII characters of a status-code URI.
func sanitizeURI(s string) string {
	var b strings.Builder

	for i := 0; i < len(s) && b.Len() < maxDiagnosticLen; i++ {
		if c := s[i]; c > 0x20 && c < 0x7f {
			b.WriteByte(c)
		}
	}

	return b.String()
}
