// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package connectrpcsec

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/hyperscale-stack/security"
)

// ErrorMapper translates a security error into a Connect error. Custom
// mappers can localize messages or attach metadata; the default mapper covers
// the canonical security sentinels.
//
// Implementations MUST be safe for concurrent use.
type ErrorMapper interface {
	// Map returns the Connect error for err. It MUST return a non-nil error
	// (callers only invoke it on a failure path).
	Map(ctx context.Context, err error) error
}

// DefaultErrorMapper returns the canonical mapper:
//
//   - connect.CodeInvalidArgument  for [security.ErrUnsupportedCredential]
//   - connect.CodePermissionDenied for [security.ErrAccessDenied] and
//     [security.ErrInsufficientScope]
//   - connect.CodeUnauthenticated  for ErrInvalidCredentials,
//     ErrClientSecretMismatch, ErrTokenExpired, ErrTokenNotFound,
//     ErrAuthenticatorRefused, and any other unclassified error
//
// The message is intentionally terse — Connect clients branch on the code,
// not the string.
func DefaultErrorMapper() ErrorMapper { return defaultErrorMapper{} }

type defaultErrorMapper struct{}

// Map implements [ErrorMapper]. The returned Connect error is the final wire
// value — not a wrapping of err — so wrapcheck is silenced here.
func (defaultErrorMapper) Map(_ context.Context, err error) error {
	code, msg := classify(err)

	return connect.NewError(code, errors.New(msg)) //nolint:wrapcheck // connect error is the terminal wire value
}

func classify(err error) (connect.Code, string) {
	switch {
	case errors.Is(err, security.ErrUnsupportedCredential):
		return connect.CodeInvalidArgument, "unsupported credential"

	case errors.Is(err, security.ErrAccessDenied):
		return connect.CodePermissionDenied, "access denied"

	case errors.Is(err, security.ErrInsufficientScope):
		return connect.CodePermissionDenied, "insufficient scope"

	case errors.Is(err, security.ErrTokenExpired):
		return connect.CodeUnauthenticated, "token expired"

	case errors.Is(err, security.ErrTokenNotFound):
		return connect.CodeUnauthenticated, "token not found"

	case errors.Is(err, security.ErrInvalidCredentials),
		errors.Is(err, security.ErrClientSecretMismatch),
		errors.Is(err, security.ErrAuthenticatorRefused):
		return connect.CodeUnauthenticated, "invalid credentials"

	default:
		return connect.CodeUnauthenticated, "unauthenticated"
	}
}
