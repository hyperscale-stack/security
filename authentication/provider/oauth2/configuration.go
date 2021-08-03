// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import "time"

// AllowedAuthorizeType is a collection of allowed auth request types
type AllowedAuthorizeType []AuthorizeRequestType

// Exists returns true if the auth type exists in the list
func (t AllowedAuthorizeType) Exists(rt AuthorizeRequestType) bool {
	for _, k := range t {
		if k == rt {
			return true
		}
	}

	return false
}

// AllowedAccessType is a collection of allowed access request types
type AllowedAccessType []AccessRequestType

// Exists returns true if the access type exists in the list
func (t AllowedAccessType) Exists(rt AccessRequestType) bool {
	for _, k := range t {
		if k == rt {
			return true
		}
	}

	return false
}

type Configuration struct {
	AuthorizationExpiration time.Duration

	AccessExpiration time.Duration

	AllowGetAccessRequest bool

	// List of allowed authorize types (only CODE by default)
	AllowedAuthorizeTypes AllowedAuthorizeType

	// List of allowed access types (only AUTHORIZATION_CODE by default)
	AllowedAccessTypes AllowedAccessType
}
