// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package httpsec

import (
	"net/http"

	"github.com/hyperscale-stack/security"
)

// Authorize returns a middleware that asks an [security.AccessDecisionManager]
// to decide whether the request may proceed. It MUST be installed AFTER
// [Middleware] so that the request context carries an [security.Authentication].
//
// On grant, the next handler runs. On deny, the configured [ErrorMapper]
// writes a response — typically 403 Forbidden. If the request never went
// through [Middleware] (no Authentication in context), the anonymous value
// is presented to the ADM, which generally denies.
func Authorize(adm security.AccessDecisionManager, attrs ...security.Attribute) func(http.Handler) http.Handler {
	return AuthorizeWith(adm, DefaultErrorMapper("Bearer", ""), attrs...)
}

// AuthorizeWith is the explicit-mapper variant of [Authorize] — useful for
// authoritative servers that want a structured error body.
func AuthorizeWith(
	adm security.AccessDecisionManager,
	mapper ErrorMapper,
	attrs ...security.Attribute,
) func(http.Handler) http.Handler {
	if mapper == nil {
		mapper = DefaultErrorMapper("Bearer", "")
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth, _ := security.FromContext(r.Context())

			if err := adm.Decide(r.Context(), auth, attrs); err != nil {
				mapper.Map(w, r, err)

				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
