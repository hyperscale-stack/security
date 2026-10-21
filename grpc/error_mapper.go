// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grpcsec

import (
	"context"

	"github.com/hyperscale-stack/security"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrorMapper translates a security error into a gRPC status error. Custom
// mappers can localize messages or attach status details; the default
// mapper covers the canonical security sentinels.
//
// Implementations MUST be safe for concurrent use.
type ErrorMapper interface {
	// Map returns the gRPC status error for err. It MUST return a non-nil
	// error (callers only invoke it on a failure path).
	Map(ctx context.Context, err error) error
}

// DefaultErrorMapper returns the canonical mapper. It answers from
// [security.ErrorClass](err) with one fixed message per code — the message
// never says why authentication failed (a token expired, a user unknown):
//
//	class                                       code              message
//	invalid_request                             InvalidArgument   "invalid request"
//	unavailable                                 Unavailable       "authentication unavailable"
//	too_many_attempts                           ResourceExhausted "too many attempts"
//	token_expired, token_not_found,
//	client_secret_mismatch, invalid_credentials,
//	authentication_required,
//	unsupported_credential                      Unauthenticated   "unauthenticated"
//	insufficient_scope, access_denied           PermissionDenied  "permission denied"
//	no_extractor, _OTHER                        Internal          "internal error"
//
// gRPC clients commonly retry Unavailable: authenticators wrap
// [security.ErrUnavailable] only for a transient dependency failure, and an
// error wrapping no security sentinel is an internal error. A throttled
// attempt ([security.ErrTooManyAttempts]) is ResourceExhausted — gRPC has
// no standard field for its retry delay.
func DefaultErrorMapper() ErrorMapper { return defaultErrorMapper{} }

type defaultErrorMapper struct{}

// Map implements [ErrorMapper]. The returned status error is the final
// wire value — not a wrapping of err — so wrapcheck is silenced here.
func (defaultErrorMapper) Map(_ context.Context, err error) error {
	code, msg := classify(security.ErrorClass(err))

	return status.Error(code, msg) //nolint:wrapcheck // status error is the terminal wire value
}

func classify(class string) (codes.Code, string) {
	switch class {
	case security.ErrorClassInvalidRequest:
		return codes.InvalidArgument, "invalid request"
	case security.ErrorClassUnavailable:
		return codes.Unavailable, "authentication unavailable"
	case security.ErrorClassTooManyAttempts:
		return codes.ResourceExhausted, "too many attempts"
	case security.ErrorClassTokenExpired, security.ErrorClassTokenNotFound,
		security.ErrorClassClientSecretMismatch, security.ErrorClassInvalidCredentials,
		security.ErrorClassAuthenticationRequired, security.ErrorClassUnsupportedCredential:
		return codes.Unauthenticated, "unauthenticated"
	case security.ErrorClassInsufficientScope, security.ErrorClassAccessDenied:
		return codes.PermissionDenied, "permission denied"
	default:
		return codes.Internal, "internal error"
	}
}
