// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package authentication

import (
	"net/http"

	"github.com/hyperscale-stack/security/authentication/credential"
)

// Handler authenticate from credential.Credential
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

				if err := provider.Authenticate(creds); err != nil {
					//TODO: bad creds
					http.Error(w, "Access denied", http.StatusUnauthorized)

					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}
