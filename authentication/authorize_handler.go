// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package authentication

import (
	"net/http"
)

// AuthorizeHandler check if user is authorize to access to resource
func AuthorizeHandler() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := FromContext(r.Context())
			if auth == nil {
				http.Error(w, "Access denied", http.StatusForbidden)

				return
			}

			if !auth.IsAuthenticated() {
				http.Error(w, "Access denied", http.StatusUnauthorized)

				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
