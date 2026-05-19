// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security

// SecurityError is the marker interface implemented by every error returned by
// this module's public API. Callers SHOULD use errors.Is/errors.As against the
// sentinel values exported here rather than relying on string matching.
//
// The unexported method securityError() prevents foreign types from
// accidentally satisfying the interface.
type SecurityError interface {
	error
	securityError()
}

// Sentinel errors. Wrap them via fmt.Errorf("...: %w", ErrXxx) when adding
// contextual information so errors.Is keeps working.
var (
	// ErrInvalidCredentials indicates that the supplied credentials could not
	// be validated (bad password, unknown user, malformed token). Maps to
	// HTTP 401 / gRPC Unauthenticated.
	ErrInvalidCredentials = newSentinel("security: invalid credentials")

	// ErrClientSecretMismatch indicates that an OAuth2 client presented a
	// secret that did not match the registered value. Maps to HTTP 401.
	ErrClientSecretMismatch = newSentinel("security: oauth2 client secret mismatch")

	// ErrTokenExpired indicates that a valid token has passed its expiry.
	// Maps to HTTP 401.
	ErrTokenExpired = newSentinel("security: token expired")

	// ErrTokenNotFound indicates that the presented token does not exist in
	// the configured storage. Maps to HTTP 401.
	ErrTokenNotFound = newSentinel("security: token not found")

	// ErrUnsupportedCredential indicates that no provider recognized the
	// credential type. Maps to HTTP 400.
	ErrUnsupportedCredential = newSentinel("security: unsupported credential type")

	// ErrNoExtractor indicates that the [Engine] was configured without any
	// [Extractor]. The Engine returns the anonymous authentication and this
	// error so that the caller can distinguish "no extractor" from "all
	// extractors found nothing".
	ErrNoExtractor = newSentinel("security: no extractor configured")

	// ErrAuthenticatorRefused is the umbrella error returned by [Manager]
	// when every supporting [Authenticator] rejected the credential. The
	// individual errors are joined via errors.Join and reachable through
	// errors.Is / errors.As.
	ErrAuthenticatorRefused = newSentinel("security: every authenticator refused the credential")

	// ErrAccessDenied indicates that authorisation voting denied access.
	// Maps to HTTP 403 / gRPC PermissionDenied.
	ErrAccessDenied = newSentinel("security: access denied")

	// ErrInsufficientScope indicates that the principal is authenticated but
	// does not carry the OAuth2 scope required for the resource. Maps to
	// HTTP 403 with the "insufficient_scope" WWW-Authenticate parameter.
	ErrInsufficientScope = newSentinel("security: insufficient scope")
)

// sentinelError is the concrete type backing every package-level sentinel.
// Keeping the type unexported guarantees that no caller can mint new values
// that satisfy SecurityError without going through this package.
type sentinelError struct {
	msg string
}

func newSentinel(msg string) *sentinelError {
	return &sentinelError{msg: msg}
}

func (e *sentinelError) Error() string  { return e.msg }
func (e *sentinelError) securityError() {}
