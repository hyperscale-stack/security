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
	// ErrCodeAlreadyUsed signals authorization-code reuse — surfaced as
	// invalid_grant per RFC 6749 §4.1.2.
	ErrCodeAlreadyUsed = newCoded(CodeInvalidGrant, "authorization code already consumed", security.ErrInvalidCredentials)
	// ErrRefreshTokenReused signals refresh-token reuse — surfaced as
	// invalid_grant per OAuth 2.0 BCP §8.10.3. Storage implementations
	// MUST also revoke the entire token family when this occurs.
	ErrRefreshTokenReused = newCoded(CodeInvalidGrant, "refresh token reused — family revoked", security.ErrInvalidCredentials)
)

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
