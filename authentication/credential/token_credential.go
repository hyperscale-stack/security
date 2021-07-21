// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package credential

import "github.com/hyperscale-stack/security/user"

// TokenCredential struct
type TokenCredential struct {
	isAuthenticated bool
	principal       interface{}
	user            user.User
}

var _ Credential = (*TokenCredential)(nil)

// NewTokenCredential constructor
func NewTokenCredential(t string) Credential {
	return &TokenCredential{
		principal: t,
	}
}

// GetCredentials that prove the principal is correct, this is usually a password
func (a *TokenCredential) GetCredentials() interface{} {
	return nil
}

// GetPrincipal The identity of the principal being authenticated.
// In the case of an authentication request with username and password,
// this would be the username.
func (a *TokenCredential) GetPrincipal() interface{} {
	return a.principal
}

// IsAuthenticated returns true if token is authenticated
func (a *TokenCredential) IsAuthenticated() bool {
	return a.isAuthenticated
}

// SetAuthenticated change token to authenticated
func (a *TokenCredential) SetAuthenticated(isAuthenticated bool) {
	a.isAuthenticated = isAuthenticated
}

// SetUser set user authenticated
func (a *TokenCredential) SetUser(user user.User) {
	a.user = user
}

// GetUser return authenticated
func (a *TokenCredential) GetUser() user.User {
	return a.user
}
