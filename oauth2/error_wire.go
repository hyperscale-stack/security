// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import "net/url"

// The wire rules of OAuth2 error responses (RFC 6749 §4.1.2.1, §4.2.2.1,
// §5.2, Appendix A.7–A.9): an error code is one or more characters of
// %x20-21 / %x23-5B / %x5D-7E, an error_description zero or more of them,
// an error_uri a URI reference of %x21 / %x23-5B / %x5D-7E. An error the
// server did not write itself — returned by a grant, a ConsentFunc or an
// Extension — is held to them before it reaches the client: a malformed
// code turns the answer into a server_error, a malformed description or
// URI is left out.

// isErrorChar reports whether c may appear in an error code or an
// error_description.
func isErrorChar(c byte) bool {
	return c == 0x20 || c == 0x21 || (c >= 0x23 && c <= 0x5B) || (c >= 0x5D && c <= 0x7E)
}

// isErrorURIChar reports whether c may appear in an error_uri.
func isErrorURIChar(c byte) bool {
	return c != 0x20 && isErrorChar(c)
}

// within reports whether every byte of s satisfies ok.
func within(s string, ok func(byte) bool) bool {
	for i := range len(s) {
		if !ok(s[i]) {
			return false
		}
	}

	return true
}

// validErrorCode reports whether code is a well-formed error code.
func validErrorCode(code string) bool {
	return code != "" && within(code, isErrorChar)
}

// wireDescription returns desc when it may travel in an error response,
// and "" otherwise.
func wireDescription(desc string) string {
	if within(desc, isErrorChar) {
		return desc
	}

	return ""
}

// wireURI returns uri when it may travel in an error response — its
// characters fit and it parses as a URI reference — and "" otherwise.
func wireURI(uri string) string {
	if !within(uri, isErrorURIChar) {
		return ""
	}

	if _, err := url.Parse(uri); err != nil {
		return ""
	}

	return uri
}

// jsonWireError returns the envelope a JSON error response (/token,
// /revoke, /introspect) carries for oe: oe itself, or a server_error
// wrapping it when its code is malformed.
func jsonWireError(oe *Error) *Error {
	if validErrorCode(oe.Code) {
		return oe
	}

	return ErrServerError.WithCause(oe)
}

// authorizeErrorCodes are the codes an authorization error response may
// carry: RFC 6749 §4.1.2.1 / §4.2.2.1 and the OpenID Connect Core 1.0
// §3.1.2.6 extensions registered for the authorization endpoint (RFC 6749
// §8.5, §11.4). Token-endpoint codes, and codes no registry ties to the
// authorization endpoint, are not among them.
var authorizeErrorCodes = map[string]struct{}{
	CodeInvalidRequest:           {},
	CodeUnauthorizedClient:       {},
	CodeAccessDenied:             {},
	CodeUnsupportedResponseType:  {},
	CodeInvalidScope:             {},
	CodeServerError:              {},
	CodeTemporarilyUnavailable:   {},
	CodeInteractionRequired:      {},
	CodeLoginRequired:            {},
	CodeAccountSelectionRequired: {},
	CodeConsentRequired:          {},
	CodeInvalidRequestURI:        {},
	CodeInvalidRequestObject:     {},
	CodeRequestNotSupported:      {},
	CodeRequestURINotSupported:   {},
	CodeRegistrationNotSupported: {},
}

// authorizeWireError returns the envelope an authorization error response
// carries for oe: oe itself when its code is one of authorizeErrorCodes,
// a server_error wrapping it otherwise.
func authorizeWireError(oe *Error) *Error {
	if _, ok := authorizeErrorCodes[oe.Code]; ok {
		return oe
	}

	return ErrServerError.WithCause(oe)
}
