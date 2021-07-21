// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package authentication

import (
	"net/http"

	"github.com/hyperscale-stack/security/authentication/credential"
)

// FilterHandler apply filters to http requests
func FilterHandler(filters ...Filter) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, filter := range filters {
				r = filter.OnFilter(r)

				if token := credential.FromContext(r.Context()); token != nil {
					next.ServeHTTP(w, r)

					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}
