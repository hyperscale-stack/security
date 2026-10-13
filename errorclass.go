// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security

import (
	"errors"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// Error classes returned by [ErrorClass]. They are the values of the
// OpenTelemetry error.type attribute set on the failing spans of the core,
// and the transport adapters map each class to a status code:
//
//	class                                   HTTP  gRPC / Connect
//	invalid_request                         400   InvalidArgument
//	unavailable                             503   Unavailable
//	token_expired, token_not_found,
//	client_secret_mismatch,
//	invalid_credentials                     401   Unauthenticated
//	authentication_required,
//	unsupported_credential                  401   Unauthenticated
//	insufficient_scope, access_denied       403   PermissionDenied
//	no_extractor, _OTHER                    500   Internal
const (
	// ErrorClassInvalidRequest is the class of [ErrInvalidRequest].
	ErrorClassInvalidRequest = "invalid_request"
	// ErrorClassUnavailable is the class of [ErrUnavailable].
	ErrorClassUnavailable = "unavailable"
	// ErrorClassTokenExpired is the class of [ErrTokenExpired].
	ErrorClassTokenExpired = "token_expired"
	// ErrorClassTokenNotFound is the class of [ErrTokenNotFound].
	ErrorClassTokenNotFound = "token_not_found"
	// ErrorClassClientSecretMismatch is the class of [ErrClientSecretMismatch].
	ErrorClassClientSecretMismatch = "client_secret_mismatch"
	// ErrorClassInvalidCredentials is the class of [ErrInvalidCredentials].
	ErrorClassInvalidCredentials = "invalid_credentials" //nolint:gosec // G101: an error class name, not a credential
	// ErrorClassAuthenticationRequired is the class of [ErrAuthenticationRequired].
	ErrorClassAuthenticationRequired = "authentication_required"
	// ErrorClassUnsupportedCredential is the class of [ErrUnsupportedCredential].
	ErrorClassUnsupportedCredential = "unsupported_credential"
	// ErrorClassInsufficientScope is the class of [ErrInsufficientScope].
	ErrorClassInsufficientScope = "insufficient_scope"
	// ErrorClassAccessDenied is the class of [ErrAccessDenied].
	ErrorClassAccessDenied = "access_denied"
	// ErrorClassNoExtractor is the class of [ErrNoExtractor].
	ErrorClassNoExtractor = "no_extractor"
	// ErrorClassOther is the class of an error that wraps no security
	// sentinel: a broken contract or an unexpected failure. It is the
	// OpenTelemetry fallback value of error.type.
	ErrorClassOther = "_OTHER"
)

// errorClasses is the classification order: the first sentinel err wraps
// names its class.
//
//   - A malformed request is refused whatever else happened.
//   - An unavailable dependency comes before any verdict on the credentials:
//     joined with another authenticator's refusal, it must not tell the
//     client to drop credentials that could be valid.
//   - A verdict on the credentials comes before an absence of credentials
//     or a bail-out, so one authenticator's refusal is never masked by
//     another one's lack of support.
//   - Authentication required comes before the access decisions, so an
//     unauthenticated principal refused by a decision is asked to
//     authenticate (401) rather than refused (403).
var errorClasses = []struct {
	err   error
	class string
}{
	{ErrInvalidRequest, ErrorClassInvalidRequest},
	{ErrUnavailable, ErrorClassUnavailable},
	{ErrTokenExpired, ErrorClassTokenExpired},
	{ErrTokenNotFound, ErrorClassTokenNotFound},
	{ErrClientSecretMismatch, ErrorClassClientSecretMismatch},
	{ErrInvalidCredentials, ErrorClassInvalidCredentials},
	{ErrAuthenticationRequired, ErrorClassAuthenticationRequired},
	{ErrUnsupportedCredential, ErrorClassUnsupportedCredential},
	{ErrInsufficientScope, ErrorClassInsufficientScope},
	{ErrAccessDenied, ErrorClassAccessDenied},
	{ErrNoExtractor, ErrorClassNoExtractor},
}

// ErrorClass returns the class of err — one of the ErrorClass* constants —
// following one precedence for every transport, joined errors included: the
// default HTTP, gRPC and ConnectRPC error mappers answer from it, and so
// should a custom mapper. It returns "" for a nil error and
// [ErrorClassOther] for an error that wraps no security sentinel.
// [ErrAuthenticatorRefused] is not a class: it is classified by the
// refusals it joins.
//
// The class is a low-cardinality name free of user input: it is safe to
// record on spans and logs, unlike the error text.
func ErrorClass(err error) string {
	if err == nil {
		return ""
	}

	for _, c := range errorClasses {
		if errors.Is(err, c.err) {
			return c.class
		}
	}

	return ErrorClassOther
}

// recordFailure marks span as failed with the class of err only: the error
// text may hold user input (a username, a store error) and is never
// recorded — neither as the status description nor as an exception event.
func recordFailure(span trace.Span, err error) {
	class := ErrorClass(err)

	span.SetStatus(codes.Error, class)
	span.SetAttributes(AttrErrorType.String(class))
}
