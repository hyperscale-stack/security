// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package authentication

// UsernamePasswordAuthentication struct
type UsernamePasswordAuthentication struct {
	isAuthenticated bool
	credentials     interface{}
	principal       interface{}
}

var _ Authentication = (*UsernamePasswordAuthentication)(nil)

// NewUsernamePasswordAuthentication constructor
func NewUsernamePasswordAuthentication(principal string, credentials string) Authentication {
	return &UsernamePasswordAuthentication{
		credentials: credentials,
		principal:   principal,
	}
}

// GetCredentials that prove the principal is correct, this is usually a password
func (a *UsernamePasswordAuthentication) GetCredentials() interface{} {
	return a.credentials
}

// GetPrincipal The identity of the principal being authenticated.
// In the case of an authentication request with username and password,
// this would be the username.
func (a *UsernamePasswordAuthentication) GetPrincipal() interface{} {
	return a.principal
}

// IsAuthenticated returns true if token is authenticated
func (a *UsernamePasswordAuthentication) IsAuthenticated() bool {
	return a.isAuthenticated
}

// SetAuthenticated change token to authenticated
func (a *UsernamePasswordAuthentication) SetAuthenticated(isAuthenticated bool) {
	a.isAuthenticated = isAuthenticated
}
