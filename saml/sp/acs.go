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
	"net/http"
	"net/url"
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
// In order, without side effects until step 10:
//
//  1. the request: POST, form content type, body within MaxResponseSize, one
//     SAMLResponse, at most one RelayState that must be a handle issued by
//     BeginLogin — otherwise the response is unsolicited (IdP-initiated SSO
//     is refused, Profiles §4.1.5, errata E90);
//  2. the browser-binding cookie must be present;
//  3. the SAMLResponse is base64-decoded (line breaks tolerated), never
//     inflated (DEFLATE is a Redirect binding encoding);
//  4. the connection (from the application's route) is resolved and
//     validated; the request path must be its ACS path (Bindings §3.5.5.2);
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
//     be unconsumed, belong to this browser (constant-time comparison of the
//     cookie digest), be unexpired, and its connection, IdP entity ID, SP
//     entity ID and ACS must still match;
//  7. a non-Success status yields a [*StatusError] carrying the AppState;
//  8. the signatures are verified by gosaml2/goxmldsig with the
//     connection's certificates: the Response or the Assertion must be
//     signed (Profiles §4.1.3.5/§4.1.4.5 as amended by errata E93/E26) and
//     every value used afterwards comes from the verified canonical bytes;
//  9. the processing rules: Destination (required when the Response is
//     signed), Issuers, IssueInstants, Recipient, InResponseTo (the request
//     ID of the transaction), NotOnOrAfter/NotBefore with the clock skew,
//     audiences, AuthnStatement, ForceAuthn, requested context class and
//     NameID format;
//  10. the transaction is consumed atomically (one winner across
//     instances), then the assertion is recorded in the replay cache
//     (Profiles §4.1.4.5). A failure after the consumption leaves it
//     consumed: the user starts over.
//
// Every refusal matches [ErrRejected] and a specific sentinel; error
// messages never contain message content. A store or resolver failure is
// returned as is and does not match ErrRejected.
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

	if err := checkACSPath(r, conn); err != nil {
		return nil, err
	}

	raw, err := precheck(in.response, conn.InsecureAllowSHA1)
	if err != nil {
		return nil, err
	}

	rec, tx, err := sp.loadTransaction(ctx, conn, in, now)
	if err != nil {
		return nil, err
	}

	if !raw.status.success() {
		return nil, statusError(raw, tx, conn)
	}

	return sp.finish(ctx, raw, conn, rec, tx, now)
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

// readForm returns the POST form, reading at most MaxResponseSize bytes.
// A form the application already parsed (r.PostForm) is used as is.
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

// checkACSPath requires the request to arrive at the path of the
// connection's ACS URL (Bindings §3.5.5.2).
func checkACSPath(r *http.Request, conn *Connection) error {
	acs, err := url.Parse(conn.ACSURL)
	if err != nil || r.URL == nil || r.URL.Path != acs.Path {
		return reject(ErrDestinationMismatch, "request received outside the connection's ACS path", nil)
	}

	return nil
}

// loadTransaction looks up the transaction of (connection, handle) without
// consuming it, and checks the browser binding, the expiry and that the
// connection did not change since BeginLogin.
func (sp *ServiceProvider) loadTransaction(ctx context.Context, conn *Connection, in *acsInput, now time.Time,
) (*TransactionRecord, *transaction, error) {
	rec, err := sp.cfg.Transactions.LookupTransaction(ctx, transactionID(conn.ID, in.handle))

	switch {
	case errors.Is(err, ErrRejected):
		return nil, nil, reject(err, "", nil)
	case err != nil:
		return nil, nil, fmt.Errorf("samlsp: lookup transaction: %w", err)
	}

	if subtle.ConstantTimeCompare([]byte(rec.BindingHash), []byte(bindingHash(in.binding))) != 1 {
		return nil, nil, reject(ErrBrowserBindingMismatch, "", nil)
	}

	if !now.Before(rec.ExpiresAt) {
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

	return rec, tx, nil
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

// finish verifies the signatures, applies the processing rules, consumes
// the transaction and records the assertion.
func (sp *ServiceProvider) finish(ctx context.Context, raw *rawResponse, conn *Connection, rec *TransactionRecord,
	tx *transaction, now time.Time,
) (*LoginResult, error) {
	resp, err := sp.verifyResponse(raw, conn, now)
	if err != nil {
		return nil, err
	}

	v := &verified{resp: resp, raw: raw, tx: tx, conn: conn, txExpiry: rec.ExpiresAt, now: now, skew: sp.cfg.ClockSkew}

	identity, replayExpiry, err := v.check()
	if err != nil {
		return nil, err
	}

	if err := sp.cfg.Transactions.ConsumeTransaction(ctx, rec.ID, rec.BindingHash); err != nil {
		if errors.Is(err, ErrRejected) {
			return nil, reject(err, "", nil)
		}

		return nil, fmt.Errorf("samlsp: consume transaction: %w", err)
	}

	if err := sp.cfg.ReplayCache.MarkAssertionUsed(ctx, replayKey(identity.Issuer, identity.AssertionID), replayExpiry); err != nil {
		if errors.Is(err, ErrRejected) {
			return nil, reject(err, "", nil)
		}

		return nil, fmt.Errorf("samlsp: record assertion: %w", err)
	}

	return &LoginResult{Identity: *identity, AppState: tx.AppState}, nil
}
