// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package authentication

import (
	"errors"
	"net/http"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/authentication/credential"
	"github.com/rs/zerolog"
)

// Handler authenticates a request by handing the credential found in context
// (typically populated by a Filter) to the first Provider that Supports it.
//
// Semantics:
//   - if no credential is present in context, the next handler runs as
//     anonymous (the request flows through);
//   - the first provider whose IsSupported returns true is invoked, and the
//     loop stops afterwards (first-supported-wins, fixed in v0). Earlier
//     versions kept iterating, allowing later providers to overwrite the
//     authenticated state — that bug is closed here;
//   - on provider error, the request is short-circuited with HTTP 401 and the
//     legacy body "Access denied". The body will become configurable in the
//     upcoming httpsec.ErrorMapper (Phase 3);
//   - if no provider supports the credential, the request flows through as
//     anonymous and any downstream AuthorizeHandler will reject it.
func Handler(providers ...Provider) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			creds := credential.FromContext(r.Context())
			if creds == nil {
				next.ServeHTTP(w, r)

				return
			}

			for _, provider := range providers {
				if !provider.IsSupported(creds) {
					continue
				}

				updated, err := provider.Authenticate(r, creds)
				if err != nil {
					zerolog.Ctx(r.Context()).
						Warn().
						Err(err).
						Int("status", errorToStatus(err)).
						Msg("authentication provider rejected credential")

					http.Error(w, "Access denied", errorToStatus(err))

					return
				}

				r = updated

				break
			}

			next.ServeHTTP(w, r)
		})
	}
}

// errorToStatus maps a security error to an HTTP status code. Unknown errors
// default to 401 Unauthorized — the safest default for an authentication
// failure of unknown cause.
func errorToStatus(err error) int {
	switch {
	case errors.Is(err, security.ErrUnsupportedCredential):
		return http.StatusBadRequest
	case errors.Is(err, security.ErrInvalidCredentials),
		errors.Is(err, security.ErrClientSecretMismatch),
		errors.Is(err, security.ErrTokenExpired),
		errors.Is(err, security.ErrTokenNotFound):
		return http.StatusUnauthorized
	default:
		return http.StatusUnauthorized
	}
}
