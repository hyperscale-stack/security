// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package credential

import "github.com/hyperscale-stack/security/user"

// UsernamePasswordCredential struct.
type UsernamePasswordCredential struct {
	isAuthenticated bool
	credentials     interface{}
	principal       interface{}
	user            user.User
}

var _ Credential = (*UsernamePasswordCredential)(nil)

// NewUsernamePasswordCredential constructor.
func NewUsernamePasswordCredential(principal string, credentials string) *UsernamePasswordCredential {
	return &UsernamePasswordCredential{
		credentials: credentials,
		principal:   principal,
	}
}

// GetCredentials that prove the principal is correct, this is usually a password.
func (a *UsernamePasswordCredential) GetCredentials() interface{} {
	return a.credentials
}

// GetPrincipal The identity of the principal being authenticated.
// In the case of an authentication request with username and password,
// this would be the username.
func (a *UsernamePasswordCredential) GetPrincipal() interface{} {
	return a.principal
}

// IsAuthenticated returns true if token is authenticated.
func (a *UsernamePasswordCredential) IsAuthenticated() bool {
	return a.isAuthenticated
}

// SetAuthenticated change token to authenticated.
func (a *UsernamePasswordCredential) SetAuthenticated(isAuthenticated bool) {
	a.isAuthenticated = isAuthenticated
}

// SetUser set user authenticated.
func (a *UsernamePasswordCredential) SetUser(user user.User) {
	a.user = user
}

// GetUser return authenticated.
func (a *UsernamePasswordCredential) GetUser() user.User {
	return a.user
}
