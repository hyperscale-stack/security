// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package httpsec

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/hyperscale-stack/security"
)

// ErrorMapper translates a security error into an HTTP response. Custom
// mappers can produce structured (JSON, ProtoBuf) error bodies or emit
// transport-specific challenges.
//
// Implementations MUST be safe for concurrent use and MUST write the
// response status before any body bytes.
type ErrorMapper interface {
	Map(w http.ResponseWriter, r *http.Request, err error)
}

// DefaultErrorMapper returns the canonical mapper used by the [Middleware]
// when WithErrorMapper is not supplied. It produces:
//
//   - 400 Bad Request          for [security.ErrUnsupportedCredential]
//   - 401 Unauthorized         for ErrInvalidCredentials, ErrClientSecretMismatch,
//     ErrTokenExpired, ErrTokenNotFound,
//     ErrAuthenticatorRefused, and any other
//     non-classified error
//   - 403 Forbidden            for ErrAccessDenied
//   - 403 Forbidden with `error="insufficient_scope"` for ErrInsufficientScope
//
// 401 and 403 responses carry a WWW-Authenticate header following RFC 7235
// (challenge scheme + realm) and RFC 6750 §3 (error / error_description for
// OAuth2 bearer flows).
func DefaultErrorMapper(scheme, realm string) ErrorMapper {
	if scheme == "" {
		scheme = "Bearer"
	}

	return &defaultErrorMapper{scheme: scheme, realm: realm}
}

type defaultErrorMapper struct {
	scheme string
	realm  string
}

// Map implements [ErrorMapper].
func (m *defaultErrorMapper) Map(w http.ResponseWriter, _ *http.Request, err error) {
	status, oauthErr := classify(err)

	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		w.Header().Set("WWW-Authenticate", m.challenge(oauthErr, err))
	}

	http.Error(w, http.StatusText(status), status)
}

// challenge formats an RFC 7235 / RFC 6750 challenge string. oauthErr, when
// non-empty, populates the `error` parameter so OAuth2 clients can react
// programmatically (typical values: "invalid_token", "insufficient_scope").
func (m *defaultErrorMapper) challenge(oauthErr string, err error) string {
	out := m.scheme

	if m.realm != "" {
		out += fmt.Sprintf(" realm=%q", m.realm)
	}

	if oauthErr != "" {
		sep := " "
		if m.realm != "" {
			sep = ", "
		}

		out += sep + fmt.Sprintf("error=%q", oauthErr)

		if msg := errors.Unwrap(err); msg != nil {
			out += fmt.Sprintf(`, error_description=%q`, msg.Error())
		}
	}

	return out
}

// classify maps an error to (httpStatus, oauthErrorCode). The oauthErrorCode
// is populated only for the cases RFC 6750 §3.1 calls out.
func classify(err error) (int, string) {
	switch {
	case errors.Is(err, security.ErrUnsupportedCredential):
		return http.StatusBadRequest, ""

	case errors.Is(err, security.ErrAccessDenied):
		return http.StatusForbidden, ""

	case errors.Is(err, security.ErrInsufficientScope):
		return http.StatusForbidden, "insufficient_scope"

	case errors.Is(err, security.ErrTokenExpired),
		errors.Is(err, security.ErrTokenNotFound):
		return http.StatusUnauthorized, "invalid_token"

	case errors.Is(err, security.ErrInvalidCredentials),
		errors.Is(err, security.ErrClientSecretMismatch),
		errors.Is(err, security.ErrAuthenticatorRefused):
		return http.StatusUnauthorized, ""

	default:
		return http.StatusUnauthorized, ""
	}
}
