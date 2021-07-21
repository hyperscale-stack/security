// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package authorization

import (
	"net/http"

	"github.com/hyperscale-stack/security/authentication/credential"
)

// AuthorizeHandler check if user is authorize to access to resource
func AuthorizeHandler(options ...Option) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			creds := credential.FromContext(r.Context())
			if creds == nil {
				http.Error(w, "Access denied", http.StatusUnauthorized)

				return
			}

			if !creds.IsAuthenticated() {
				http.Error(w, "Access denied", http.StatusUnauthorized)

				return
			}

			for _, opt := range options {
				if !opt(creds) {
					http.Error(w, "Access denied", http.StatusForbidden)

					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}
