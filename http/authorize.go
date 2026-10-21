// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package httpsec

import (
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/hyperscale-stack/security"
)

// Authorize returns a middleware that asks an [security.AccessDecisionManager]
// to decide whether the request may proceed. It MUST be installed AFTER
// [Middleware] so that the request context carries an [security.Authentication].
//
// On grant, the next handler runs. On deny, it answers with the error mapper
// of the [Middleware] that ran before it — same challenge scheme and realm —
// or, without one, [DefaultErrorMapper]("Bearer", [DefaultRealm]): 403 for an
// authenticated principal, 401 with a challenge for an unauthenticated one
// (RFC 9110 §15.5.2, §15.5.4: it lacks credentials, it is asked for them).
// Authorize copies attrs, and panics if adm or one of attrs is nil (a typed
// nil included): a route's policy is static configuration.
func Authorize(adm security.AccessDecisionManager, attrs ...security.Attribute) func(http.Handler) http.Handler {
	return AuthorizeWith(adm, nil, attrs...)
}

// AuthorizeWith is the explicit-mapper variant of [Authorize] — useful for
// authoritative servers that want a structured error body. A nil mapper, a
// typed nil included, behaves like [Authorize].
func AuthorizeWith(
	adm security.AccessDecisionManager,
	mapper ErrorMapper,
	attrs ...security.Attribute,
) func(http.Handler) http.Handler {
	attrs = mustPolicy(adm, attrs)
	fallback := DefaultErrorMapper(defaultChallengeScheme, DefaultRealm)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth, _ := security.FromContext(r.Context())

			if err := adm.Decide(r.Context(), auth, attrs); err != nil {
				m := mapper
				if isNil(m) {
					var ok bool
					if m, ok = errorMapperFrom(r.Context()); !ok {
						m = fallback
					}
				}

				m.Map(w, r, refusal(auth, err))

				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// mustPolicy checks the static configuration of [Authorize] and returns a
// copy of attrs, so the caller reusing its slice cannot rewrite the policy.
func mustPolicy(adm security.AccessDecisionManager, attrs []security.Attribute) []security.Attribute {
	if isNil(adm) {
		panic("httpsec: Authorize: nil AccessDecisionManager")
	}

	for i, a := range attrs {
		if isNil(a) {
			panic(fmt.Sprintf("httpsec: Authorize: nil Attribute at index %d", i))
		}
	}

	return slices.Clone(attrs)
}

// refusal turns an access denial of an unauthenticated principal into
// "authentication required": the caller lacks credentials and is asked for
// them (401) rather than refused (403). Any other error passes through.
func refusal(auth security.Authentication, err error) error {
	denied := errors.Is(err, security.ErrAccessDenied) || errors.Is(err, security.ErrInsufficientScope)
	if denied && !auth.IsAuthenticated() {
		return fmt.Errorf("%w: %w", security.ErrAuthenticationRequired, err)
	}

	return err
}
