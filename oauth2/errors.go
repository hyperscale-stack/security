// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"errors"
	"fmt"

	"github.com/hyperscale-stack/security"
)

// Error is the OAuth2 error envelope (RFC 6749 §5.2). It carries the
// machine-readable code, an optional human description, and an optional URI
// pointing to extended documentation. Implementations of [Server] return
// values of this type so the HTTP layer can serialize them as JSON.
type Error struct {
	// Code is the RFC 6749 §5.2 error identifier ("invalid_request",
	// "invalid_client", ...).
	Code string
	// Description is the optional ASCII description displayed to the
	// client.
	Description string
	// URI is the optional documentation URL.
	URI string
	// Cause is the wrapped Go error for server-side inspection. Never
	// surfaced to the client.
	Cause error
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("oauth2: %s: %s", e.Code, e.Description)
	}

	return "oauth2: " + e.Code
}

// Unwrap exposes the embedded cause to errors.Is / errors.As.
func (e *Error) Unwrap() error { return e.Cause }

// HTTPStatus returns the canonical HTTP status code for this error per
// RFC 6749 §5.2 / RFC 7009 / RFC 7662.
func (e *Error) HTTPStatus() int {
	switch e.Code {
	case CodeInvalidClient:
		return 401
	case CodeAccessDenied:
		return 403
	case CodeServerError:
		return 500
	case CodeTemporarilyUnavailable:
		return 503
	default:
		return 400
	}
}

// RFC 6749 §5.2 error codes plus the RFC 8693 / 7591 extensions used by
// the modular OAuth2 server.
const (
	CodeInvalidRequest          = "invalid_request"
	CodeInvalidClient           = "invalid_client"
	CodeInvalidGrant            = "invalid_grant"
	CodeInvalidScope            = "invalid_scope"
	CodeUnauthorizedClient      = "unauthorized_client"
	CodeUnsupportedGrantType    = "unsupported_grant_type"
	CodeUnsupportedResponseType = "unsupported_response_type"
	CodeAccessDenied            = "access_denied"
	CodeServerError             = "server_error"
	CodeTemporarilyUnavailable  = "temporarily_unavailable"
)

// The OpenID Connect Core 1.0 §3.1.2.6 error codes, registered in the IANA
// OAuth Extensions Error Registry for the authorization endpoint (RFC 6749
// §8.5). Like the RFC 6749 §4.1.2.1 codes, they may travel back to the
// client in an authorization error response — a [Consent.Refusal], or an
// error an [Extension] returns.
const (
	CodeInteractionRequired      = "interaction_required"
	CodeLoginRequired            = "login_required"
	CodeAccountSelectionRequired = "account_selection_required"
	CodeConsentRequired          = "consent_required"
	CodeInvalidRequestURI        = "invalid_request_uri"
	CodeInvalidRequestObject     = "invalid_request_object"
	CodeRequestNotSupported      = "request_not_supported"
	CodeRequestURINotSupported   = "request_uri_not_supported"
	CodeRegistrationNotSupported = "registration_not_supported"
)

// Sentinels for the OpenID Connect Core 1.0 §3.1.2.6 error codes — the
// answers to an authentication request that cannot be completed without
// interaction (prompt=none) or that uses a parameter the server does not
// support. They read 400 through HTTPStatus but are meant to be
// redirected: return one as a [Consent.Refusal].
var (
	// ErrInteractionRequired -> interaction_required: the request needs
	// some end-user interaction.
	ErrInteractionRequired = newCoded(CodeInteractionRequired, "end-user interaction is required", security.ErrAccessDenied)
	// ErrLoginRequired -> login_required: the request needs the end-user to
	// authenticate.
	ErrLoginRequired = newCoded(CodeLoginRequired, "end-user authentication is required", security.ErrAccessDenied)
	// ErrAccountSelectionRequired -> account_selection_required: the
	// end-user must select one of their sessions.
	ErrAccountSelectionRequired = newCoded(CodeAccountSelectionRequired,
		"end-user account selection is required", security.ErrAccessDenied)
	// ErrConsentRequired -> consent_required: the request needs the
	// end-user's consent.
	ErrConsentRequired = newCoded(CodeConsentRequired, "end-user consent is required", security.ErrAccessDenied)
	// ErrInvalidRequestURI -> invalid_request_uri: the request_uri
	// returns an error or invalid data.
	ErrInvalidRequestURI = newCoded(CodeInvalidRequestURI, "the request_uri is invalid", security.ErrInvalidCredentials)
	// ErrInvalidRequestObject -> invalid_request_object: the request
	// parameter carries an invalid request object.
	ErrInvalidRequestObject = newCoded(CodeInvalidRequestObject, "the request object is invalid", security.ErrInvalidCredentials)
	// ErrRequestNotSupported -> request_not_supported: the request
	// parameter is not supported.
	ErrRequestNotSupported = newCoded(CodeRequestNotSupported,
		"the request parameter is not supported", security.ErrUnsupportedCredential)
	// ErrRequestURINotSupported -> request_uri_not_supported: the
	// request_uri parameter is not supported.
	ErrRequestURINotSupported = newCoded(CodeRequestURINotSupported,
		"the request_uri parameter is not supported", security.ErrUnsupportedCredential)
	// ErrRegistrationNotSupported -> registration_not_supported: the
	// registration parameter is not supported.
	ErrRegistrationNotSupported = newCoded(CodeRegistrationNotSupported,
		"the registration parameter is not supported", security.ErrUnsupportedCredential)
)

// Sentinel constructors returning *Error values. They wrap the core security
// sentinels so HTTP / gRPC error mappers route them to the right status.
var (
	// ErrInvalidRequest -> 400 invalid_request.
	ErrInvalidRequest = newCoded(CodeInvalidRequest, "the request is malformed", security.ErrInvalidCredentials)
	// ErrInvalidClient -> 401 invalid_client.
	ErrInvalidClient = newCoded(CodeInvalidClient, "client authentication failed", security.ErrClientSecretMismatch)
	// ErrInvalidGrant -> 400 invalid_grant.
	ErrInvalidGrant = newCoded(CodeInvalidGrant, "the grant is invalid or expired", security.ErrInvalidCredentials)
	// ErrInvalidScope -> 400 invalid_scope.
	ErrInvalidScope = newCoded(CodeInvalidScope, "the requested scope is invalid", security.ErrInvalidCredentials)
	// ErrUnauthorizedClient -> 400 unauthorized_client.
	ErrUnauthorizedClient = newCoded(CodeUnauthorizedClient, "the client is not authorized to use this grant", security.ErrInvalidCredentials)
	// ErrUnsupportedGrantType -> 400 unsupported_grant_type.
	ErrUnsupportedGrantType = newCoded(CodeUnsupportedGrantType, "the grant type is unsupported", security.ErrUnsupportedCredential)
	// ErrUnsupportedResponseType -> 400 unsupported_response_type.
	ErrUnsupportedResponseType = newCoded(CodeUnsupportedResponseType, "the response type is unsupported", security.ErrUnsupportedCredential)
	// ErrAccessDenied -> 403 access_denied.
	ErrAccessDenied = newCoded(CodeAccessDenied, "the resource owner denied the request", security.ErrAccessDenied)
	// ErrServerError -> 500 server_error.
	ErrServerError = newCoded(CodeServerError, "internal server error", nil)
	// ErrCodeAlreadyUsed signals an unknown or already consumed
	// authorization code — surfaced as invalid_grant per RFC 6749 §4.1.2.
	// On a replay, stores return it wrapped in a [*CodeReplayError]
	// carrying the retained record.
	ErrCodeAlreadyUsed = newCoded(CodeInvalidGrant, "authorization code already consumed", security.ErrInvalidCredentials)
	// ErrRefreshTokenReused signals refresh-token reuse — surfaced as
	// invalid_grant per RFC 9700 §4.14.2. Storage implementations MUST also
	// revoke the entire token family when this occurs; when that revocation
	// fails, the error also wraps [ErrTokenFamilyRevocationFailed].
	ErrRefreshTokenReused = newCoded(CodeInvalidGrant, "refresh token reused", security.ErrInvalidCredentials)
	// ErrTokenFamilyRevoked signals an operation on a token family that has
	// been revoked — surfaced as invalid_grant (RFC 6749 §5.2: the grant
	// was revoked).
	ErrTokenFamilyRevoked = newCoded(CodeInvalidGrant, "token family revoked", security.ErrInvalidCredentials)
)

// ErrTokenFamilyRevocationFailed reports that a token family could not be
// recorded as revoked: the family MUST be treated as still active, and the
// revocation retried (it is idempotent). It is a plain sentinel, not an
// [*Error], so it never reaches the wire on its own — a caller that turns
// it into a response answers server_error. Stores wrap it, with the
// family ID and the backend cause, in the error RevokeRefreshFamily
// returns, and after [ErrRefreshTokenReused] when the revocation a reuse
// triggers fails; match it with errors.Is.
var ErrTokenFamilyRevocationFailed = errors.New("oauth2: token family revocation failed")

// CodeReplayError is the error an [AuthorizationCodeStore] returns for a
// code it consumed before and still retains: a replay (RFC 6749 §4.1.2).
// It reads and matches as [ErrCodeAlreadyUsed] — errors.Is, [IsCode] and
// the RFC 6749 §5.2 response all see invalid_grant — and carries the
// retained record, so the authorization_code grant can revoke the tokens
// the first exchange issued. The record MUST NOT be used to issue tokens.
// Wrapping it with %w keeps it reachable through errors.As.
type CodeReplayError struct {
	// Record is the replayed code as it was saved, without the raw Code.
	Record *AuthorizationCode
}

// Error implements the error interface with the text of
// [ErrCodeAlreadyUsed].
func (e *CodeReplayError) Error() string { return ErrCodeAlreadyUsed.Error() }

// Unwrap returns [ErrCodeAlreadyUsed].
func (e *CodeReplayError) Unwrap() error { return ErrCodeAlreadyUsed }

// newCoded constructs an Error sentinel. The cause chain reaches the supplied
// security sentinel via Unwrap so errors.Is keeps working transparently.
func newCoded(code, desc string, cause error) *Error {
	return &Error{Code: code, Description: desc, Cause: cause}
}

// IsCode returns the OAuth2 error code embedded in err, or "" when err is
// not an [*Error] in its chain.
func IsCode(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}

	return ""
}

// WithDescription returns a copy of e with the human-readable description
// replaced. Sentinels stay immutable so concurrent reads remain safe.
func (e *Error) WithDescription(desc string) *Error {
	cp := *e
	cp.Description = desc

	return &cp
}

// WithCause returns a copy of e with the wrapped cause set to err. The
// resulting Error wraps both the original security sentinel (via the chain)
// and the new cause, so errors.Is / errors.As keeps working in both
// directions.
func (e *Error) WithCause(err error) *Error {
	cp := *e
	cp.Cause = errors.Join(e.Cause, err)

	return &cp
}
