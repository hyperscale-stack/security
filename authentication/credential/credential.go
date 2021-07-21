// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package credential

import "github.com/hyperscale-stack/security/user"

// Credential interface
type Credential interface {
	GetPrincipal() interface{}
	GetCredentials() interface{}
	IsAuthenticated() bool
	SetAuthenticated(isAuthenticated bool)
	SetUser(user user.User)
	GetUser() user.User
}
