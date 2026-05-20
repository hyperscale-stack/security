// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grpcsec

import (
	"context"
	"errors"

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

// DefaultErrorMapper returns the canonical mapper:
//
//   - codes.InvalidArgument  for [security.ErrUnsupportedCredential]
//   - codes.PermissionDenied for [security.ErrAccessDenied] and
//     [security.ErrInsufficientScope]
//   - codes.Unauthenticated  for ErrInvalidCredentials,
//     ErrClientSecretMismatch, ErrTokenExpired, ErrTokenNotFound,
//     ErrAuthenticatorRefused, and any other unclassified error
//
// The message is intentionally terse — gRPC clients branch on the code,
// not the string.
func DefaultErrorMapper() ErrorMapper { return defaultErrorMapper{} }

type defaultErrorMapper struct{}

// Map implements [ErrorMapper]. The returned status error is the final
// wire value — not a wrapping of err — so wrapcheck is silenced here.
func (defaultErrorMapper) Map(_ context.Context, err error) error {
	code, msg := classify(err)

	return status.Error(code, msg) //nolint:wrapcheck // status error is the terminal wire value
}

func classify(err error) (codes.Code, string) {
	switch {
	case errors.Is(err, security.ErrUnsupportedCredential):
		return codes.InvalidArgument, "unsupported credential"

	case errors.Is(err, security.ErrAccessDenied):
		return codes.PermissionDenied, "access denied"

	case errors.Is(err, security.ErrInsufficientScope):
		return codes.PermissionDenied, "insufficient scope"

	case errors.Is(err, security.ErrTokenExpired):
		return codes.Unauthenticated, "token expired"

	case errors.Is(err, security.ErrTokenNotFound):
		return codes.Unauthenticated, "token not found"

	case errors.Is(err, security.ErrInvalidCredentials),
		errors.Is(err, security.ErrClientSecretMismatch),
		errors.Is(err, security.ErrAuthenticatorRefused):
		return codes.Unauthenticated, "invalid credentials"

	default:
		return codes.Unauthenticated, "unauthenticated"
	}
}
