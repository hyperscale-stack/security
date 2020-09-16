// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package authentication

// TokenAuthentication struct
type TokenAuthentication struct {
	isAuthenticated bool
	principal       interface{}
}

var _ Authentication = (*TokenAuthentication)(nil)

// NewTokenAuthentication constructor
func NewTokenAuthentication(token string) Authentication {
	return &TokenAuthentication{
		principal: token,
	}
}

// GetCredentials that prove the principal is correct, this is usually a password
func (a *TokenAuthentication) GetCredentials() interface{} {
	return nil
}

// GetPrincipal The identity of the principal being authenticated.
// In the case of an authentication request with username and password,
// this would be the username.
func (a *TokenAuthentication) GetPrincipal() interface{} {
	return a.principal
}

// IsAuthenticated returns true if token is authenticated
func (a *TokenAuthentication) IsAuthenticated() bool {
	return a.isAuthenticated
}

// SetAuthenticated change token to authenticated
func (a *TokenAuthentication) SetAuthenticated(isAuthenticated bool) {
	a.isAuthenticated = isAuthenticated
}
