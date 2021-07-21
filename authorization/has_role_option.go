// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package authorization

import "github.com/hyperscale-stack/security/authentication/credential"

// HasRole check if user has role.
func HasRole(role string) Option {
	return func(creds credential.Credential) bool {
		user := creds.GetUser()

		if user == nil {
			return false
		}

		roles := user.GetRoles()

		for _, r := range roles {
			if r == role {
				return true
			}
		}

		return false
	}
}
