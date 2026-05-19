// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package credential

import "github.com/hyperscale-stack/security/user"

// Credential is the legacy mutable credential interface based on interface{}
// principals/credentials.
//
// Deprecated: use [security.Authentication] (in the parent module) instead.
// It is immutable and type-safe through scheme-specific helpers.
// Scheduled for removal at the end of Phase 7.
type Credential interface {
	GetPrincipal() interface{}
	GetCredentials() interface{}
	IsAuthenticated() bool
	SetAuthenticated(isAuthenticated bool)
	SetUser(user user.User)
	GetUser() user.User
}
