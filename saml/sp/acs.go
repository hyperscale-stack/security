// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// LoginResult is the outcome of a successful login.
type LoginResult struct {
	// Identity is the verified identity.
	Identity Identity
	// AppState is the LoginOptions.AppState of the transaction.
	AppState string
}

// CompleteLogin consumes the SAML Response delivered by the browser to the
// assertion consumer service of a connection (HTTP-POST binding, Bindings
// §3.5), and returns the verified identity. The application routes the ACS
// URL of each connection to it, passing the connection ID taken from its
// route; it MUST exempt this endpoint from its own CSRF protection (the
// POST comes from the IdP's page) and SHOULD answer a rejection with a
// generic error page (Bindings §3.5.6 forbids HTTP error codes for SAML
// processing failures). CompleteLogin writes no HTTP response.
//
// In order, without side effects until step 8:
//
//  1. the request: POST, form content type, body within MaxResponseSize (or,
//     for a form the application already parsed, the SAMLResponse value),
//     one SAMLResponse, at most one RelayState that must be a handle issued
//     by BeginLogin — otherwise the response is unsolicited (IdP-initiated
//     SSO is refused, Profiles §4.1.5, errata E90);
//  2. the browser-binding cookie must be present;
//  3. the SAMLResponse is base64-decoded (line breaks tolerated), never
//     inflated (DEFLATE is a Redirect binding encoding);
//  4. the connection (from the application's route) is resolved and
//     validated; the request must have been received at its ACS URL — same
//     path, same host (r.Host, never a forwarding header), no query string
//     (Core §3.2.2, Bindings §3.5.5.2); when the connection sets
//     ResponseOrigins, the request's Origin (or, without one, its Referer's
//     origin) must be one of them;
//  5. the lexical gate (no DTD or processing instruction, bounded elements,
//     tokens, depth, attributes, namespace declarations and prefixes,
//     attribute value lengths, unique attributes, declared prefixes), then
//     the structural profile: one Response with a Status, unique IDs, no
//     encrypted content, UTC time values, and for a Success: exactly one
//     Assertion child of the Response, one Issuer each, the SAML XML-DSig
//     profile and algorithm policy on every signature, one bearer
//     SubjectConfirmation without NotBefore, one AuthnStatement, understood
//     Conditions only;
//  6. the transaction (connection, RelayState) is looked up: it must exist,
//     be unconsumed, carry a valid integrity MAC under one of
//     Config.TransactionKeys (verified before any stored field is used),
//     belong to this browser (constant-time comparison of the cookie
//     digest), be unexpired, and its connection, IdP entity ID, SP entity
//     ID and ACS must still match;
//  7. a non-Success status yields a [*StatusError] carrying the AppState;
//     a Success Response must answer the transaction's request in its own
//     InResponseTo (Core §3.2.2);
//  8. the transaction is consumed atomically (one winner across
//     instances), under the ID derived from the request and the digest of
//     the cookie the browser presented: a login allows one verification,
//     and from here every refusal is final — the user starts over;
//  9. the signatures are verified by gosaml2/goxmldsig with the
//     connection's certificates: the Response or the Assertion must be
//     signed (Profiles §4.1.3.5/§4.1.4.5 as amended by errata E93/E26) and
//     every value used afterwards comes from the verified canonical bytes;
//     a signature without KeyInfo tries the certificate that verified the
//     connection's last such signature first;
//  10. the processing rules: Destination (required when the Response is
//     signed), Issuers, IssueInstants, Recipient, InResponseTo (the request
//     ID of the transaction), NotOnOrAfter/NotBefore with the clock skew,
//     audiences, AuthnStatement, ForceAuthn, requested context class and
//     NameID format;
//  11. the assertion is recorded in the replay cache (Profiles §4.1.4.5).
//
// Every refusal matches [ErrRejected] and a specific sentinel; error
// messages never contain message content. A store or resolver failure is
// returned as is and does not match ErrRejected. A refusal before step 8
// leaves the transaction to its browser; from step 8 on, the span carries
// samlsp.transaction_consumed (AttrTransactionConsumed).
func (sp *ServiceProvider) CompleteLogin(ctx context.Context, r *http.Request, connectionID string) (_ *LoginResult, err error) {
	ctx, span := startSpan(ctx, "samlsp.ServiceProvider.CompleteLogin")
	defer func() { endSpan(span, err) }()

	if r == nil {
		return nil, fmt.Errorf("%w: CompleteLogin needs a Request", ErrInvalidConfig)
	}

	now := sp.cfg.Now()

	in, err := sp.readACSRequest(r)
	if err != nil {
		return nil, err
	}

	conn, err := sp.resolveForACS(ctx, connectionID, now)
	if err != nil {
		return nil, err
	}

	annotateConnection(span, conn)

	if err := checkACSLocation(r, conn); err != nil {
		return nil, err
	}

	if err := checkResponseOrigin(r, conn.ResponseOrigins); err != nil {
		return nil, err
	}

	raw, err := precheck(in.response, conn.InsecureAllowSHA1)
	if err != nil {
		return nil, err
	}

	st, tx, err := sp.loadTransaction(ctx, conn, in, now)
	if err != nil {
		return nil, err
	}

	if !raw.status.success() {
		return nil, statusError(raw, tx, conn)
	}

	if err := checkResponseInResponseTo(raw, tx); err != nil {
		return nil, err
	}

	// From here every outcome is final for the transaction: one
	// verification per login (audit SAML-01).
	if err := sp.consume(ctx, st); err != nil {
		return nil, err
	}

	span.SetAttributes(AttrTransactionConsumed.Bool(true))

	return sp.finish(ctx, raw, conn, st, tx, now)
}

// acsInput is the decoded HTTP-POST binding request.
type acsInput struct {
	response []byte // decoded SAMLResponse
	handle   string // RelayState
	binding  string // browser-binding cookie value
}

// readACSRequest checks the request and decodes the SAMLResponse.
func (sp *ServiceProvider) readACSRequest(r *http.Request) (*acsInput, error) {
	form, err := sp.readForm(r)
	if err != nil {
		return nil, err
	}

	responses, relayStates := form[formFieldResponse], form[formFieldRelayState]
	if len(responses) != 1 || responses[0] == "" || len(relayStates) > 1 {
		return nil, reject(ErrMalformedRequest, "need one SAMLResponse and at most one RelayState", nil)
	}

	// A form the application parsed first was not read under
	// MaxResponseSize (Go's own limit is 10 MB): bound the value itself.
	if int64(len(responses[0])) > sp.cfg.MaxResponseSize {
		return nil, reject(ErrResponseTooLarge, "SAMLResponse over MaxResponseSize", nil)
	}

	in := &acsInput{}

	if len(relayStates) == 1 {
		in.handle = relayStates[0]
	}

	if !isHandle(in.handle) {
		return nil, reject(ErrUnsolicitedResponse, "RelayState is not a handle issued by BeginLogin", nil)
	}

	cookie, err := r.Cookie(sp.cfg.CookieName)
	if err != nil || !isHandle(cookie.Value) {
		return nil, reject(ErrMissingBrowserBinding, "", nil)
	}

	in.binding = cookie.Value

	decoded, err := base64.StdEncoding.DecodeString(responses[0])
	if err != nil {
		return nil, reject(ErrMalformedResponse, "SAMLResponse is not base64", nil)
	}

	in.response = stripBOM(decoded)

	return in, nil
}

// readForm returns the POST form, reading at most MaxResponseSize bytes. A
// form the application already parsed (r.PostForm) is used as it is; the
// caller bounds its SAMLResponse.
func (sp *ServiceProvider) readForm(r *http.Request) (url.Values, error) {
	if r.Method != http.MethodPost {
		return nil, reject(ErrMalformedRequest, "method is not POST", nil)
	}

	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != formMediaType {
		return nil, reject(ErrMalformedRequest, "content type is not a form", nil)
	}

	if r.PostForm != nil {
		return r.PostForm, nil
	}

	body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, sp.cfg.MaxResponseSize))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, reject(ErrResponseTooLarge, "request body over MaxResponseSize", nil)
		}

		return nil, reject(ErrMalformedRequest, "unreadable body", nil)
	}

	form, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, reject(ErrMalformedRequest, "malformed form", nil)
	}

	return form, nil
}

// resolveForACS resolves the connection; a configuration problem met here
// rejects the login, an infrastructure failure does not.
func (sp *ServiceProvider) resolveForACS(ctx context.Context, connectionID string, now time.Time) (*Connection, error) {
	conn, err := sp.resolve(ctx, connectionID)

	switch {
	case errors.Is(err, ErrUnknownConnection):
		return nil, reject(ErrUnknownConnection, "", err)
	case errors.Is(err, ErrInvalidConnection):
		return nil, reject(ErrInvalidConnection, "", err)
	case err != nil:
		return nil, err
	case conn.IdentityProvider.expired(now):
		return nil, reject(ErrMetadataExpired, "", nil)
	}

	return conn, nil
}

// checkACSLocation requires the request to have been received at the
// connection's ACS URL, which the Destination and the Recipient must name:
// Core §3.2.2 ("the actual recipient MUST check that the URI reference
// identifies the location at which the message was received"), Bindings
// §3.5.5.2, Profiles §4.1.4.3. It compares the path in its escaped form
// (an encoded slash is not a slash), refuses any query string (the ACS URL
// has none), and compares r.Host with the URL's host, case-insensitively,
// the scheme's default port standing for an absent one. No forwarding
// header is ever read: behind a proxy that rewrites Host, the application
// passes CompleteLogin a copy of the request (http.Request.Clone) whose
// Host comes from its trusted proxy's header. The
// scheme is not visible behind a TLS-terminating proxy; the Secure,
// __Host- binding cookie, which browsers send over https only (loopback
// aside), binds it instead.
func checkACSLocation(r *http.Request, conn *Connection) error {
	acs, err := url.Parse(conn.ACSURL)

	switch {
	case err != nil || r.URL == nil || r.URL.EscapedPath() != acs.EscapedPath():
		return reject(ErrDestinationMismatch, "request received outside the connection's ACS path", nil)
	case r.URL.RawQuery != "" || r.URL.ForceQuery:
		return reject(ErrDestinationMismatch, "request received with a query string", nil)
	case !sameAuthority(r.Host, acs):
		return reject(ErrDestinationMismatch, "request received at another host than the connection's ACS URL", nil)
	}

	return nil
}

// sameAuthority reports whether a request's Host names the host and port
// of u: hosts compared case-insensitively, an absent port meaning the
// default port of u's scheme. An empty or malformed Host never matches.
func sameAuthority(host string, u *url.URL) bool {
	h, port, ok := splitAuthority(host)
	if !ok {
		return false
	}

	want := u.Port()
	if want == "" {
		want = defaultPort(u.Scheme)
	}

	if port == "" {
		port = defaultPort(u.Scheme)
	}

	return strings.EqualFold(h, u.Hostname()) && port == want
}

// splitAuthority splits a Host value into its host (IPv6 brackets removed)
// and its port ("" when absent).
func splitAuthority(host string) (string, string, bool) {
	switch {
	case host == "":
		return "", "", false
	case strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]"):
		return host[1 : len(host)-1], "", true
	case strings.HasPrefix(host, "[") || strings.Count(host, ":") == 1:
		h, port, err := net.SplitHostPort(host)

		return h, port, err == nil
	case strings.Contains(host, ":"):
		return "", "", false // an unbracketed IPv6 literal or a repeated port
	default:
		return host, "", true
	}
}

// defaultPort is the default port of an http(s) scheme.
func defaultPort(scheme string) string {
	if scheme == schemeHTTP {
		return "80"
	}

	return "443"
}

// storedTransaction is a transaction record whose integrity verified.
type storedTransaction struct {
	// id is the store key derived from the connection and the handle.
	id string
	// bindingHash is the digest of the cookie the browser presented.
	bindingHash string
	// expiresAt is the expiry the MAC covers (whole seconds).
	expiresAt time.Time
}

// loadTransaction looks up the transaction of (connection, handle) without
// consuming it, verifies its integrity MAC before any of its fields is used
// (the MAC covers the ID derived here, not the one the store returns), and
// checks the browser binding, the expiry and that the connection did not
// change since BeginLogin.
func (sp *ServiceProvider) loadTransaction(ctx context.Context, conn *Connection, in *acsInput, now time.Time,
) (*storedTransaction, *transaction, error) {
	id := transactionID(conn.ID, in.handle)
	rec, err := sp.cfg.Transactions.LookupTransaction(ctx, id)

	switch {
	case errors.Is(err, ErrRejected):
		return nil, nil, reject(err, "", nil)
	case err != nil:
		return nil, nil, fmt.Errorf("samlsp: lookup transaction: %w", err)
	case rec == nil: // a non-conformant store: nothing found
		return nil, nil, reject(ErrTransactionNotFound, "", nil)
	}

	if !verifyIntegrity(sp.cfg.TransactionKeys, id, rec) {
		return nil, nil, reject(ErrTransactionIntegrity, "", nil)
	}

	st := &storedTransaction{
		id:          id,
		bindingHash: bindingHash(in.binding),
		// The MAC covers whole seconds: a store returning a fraction more
		// cannot extend the transaction (plan review F4).
		expiresAt: time.Unix(rec.ExpiresAt.Unix(), 0).UTC(),
	}

	if subtle.ConstantTimeCompare([]byte(rec.BindingHash), []byte(st.bindingHash)) != 1 {
		return nil, nil, reject(ErrBrowserBindingMismatch, "", nil)
	}

	if !now.Before(st.expiresAt) {
		return nil, nil, reject(ErrTransactionExpired, "", nil)
	}

	tx, err := decodeTransaction(rec.Payload)
	if err != nil {
		return nil, nil, err
	}

	if tx.ConnectionID != conn.ID || tx.SP != conn.SPEntityID || tx.ACS != conn.ACSURL ||
		tx.IdP != conn.IdentityProvider.EntityID {
		return nil, nil, reject(ErrTransactionMismatch, "", nil)
	}

	return st, tx, nil
}

// checkResponseInResponseTo requires a Success response to name the request
// it answers on the Response itself: Core §3.2.2 makes InResponseTo
// mandatory in a response to a request whose ID is known, and its value
// must be that ID. It reads the value before verification, which can only
// add a refusal; checkEnvelope compares the verified value again.
func checkResponseInResponseTo(raw *rawResponse, tx *transaction) error {
	switch raw.inResponseTo {
	case tx.RequestID:
		return nil
	case "":
		return reject(ErrUnsolicitedResponse, "no InResponseTo on the Response", nil)
	default:
		return reject(ErrInResponseToMismatch, "Response InResponseTo is not the request ID", nil)
	}
}

// statusError reports a non-Success response bound to the transaction.
func statusError(raw *rawResponse, tx *transaction, conn *Connection) error {
	if raw.inResponseTo != "" && raw.inResponseTo != tx.RequestID {
		return reject(ErrInResponseToMismatch, "Response InResponseTo is not the request ID", nil)
	}

	return &StatusError{
		Code:         raw.status.code,
		SubCode:      raw.status.subCode,
		Message:      raw.status.message,
		ConnectionID: conn.ID,
		AppState:     tx.AppState,
	}
}

// consume marks the transaction consumed, under the ID derived from the
// request and the digest of the cookie the browser presented: the store
// compares it with the stored one again, under its own atomicity (audit
// SAML-I8). Of concurrent calls, one wins; the others are refused.
func (sp *ServiceProvider) consume(ctx context.Context, st *storedTransaction) error {
	if err := sp.cfg.Transactions.ConsumeTransaction(ctx, st.id, st.bindingHash); err != nil {
		if errors.Is(err, ErrRejected) {
			return reject(err, "", nil)
		}

		return fmt.Errorf("samlsp: consume transaction: %w", err)
	}

	return nil
}

// finish verifies the signatures of a response whose transaction is
// consumed, applies the processing rules and records the assertion.
func (sp *ServiceProvider) finish(ctx context.Context, raw *rawResponse, conn *Connection, st *storedTransaction,
	tx *transaction, now time.Time,
) (*LoginResult, error) {
	resp, err := sp.verifyResponse(raw, conn, now)
	if err != nil {
		return nil, err
	}

	v := &verified{resp: resp, raw: raw, tx: tx, conn: conn, txExpiry: st.expiresAt, now: now, skew: sp.cfg.ClockSkew}

	identity, replayExpiry, err := v.check()
	if err != nil {
		return nil, err
	}

	key := replayKey(conn.ID, identity.Issuer, identity.AssertionID)

	if err := sp.cfg.ReplayCache.MarkAssertionUsed(ctx, key, replayExpiry); err != nil {
		if errors.Is(err, ErrRejected) {
			return nil, reject(err, "", nil)
		}

		return nil, fmt.Errorf("samlsp: record assertion: %w", err)
	}

	return &LoginResult{Identity: *identity, AppState: tx.AppState}, nil
}
