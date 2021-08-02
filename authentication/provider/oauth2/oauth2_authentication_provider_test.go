// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"testing"

	"github.com/hyperscale-stack/security/authentication/credential"
	"github.com/hyperscale-stack/security/user"
	"github.com/stretchr/testify/assert"
)

// BadCredential struct.
type BadCredential struct {
	isAuthenticated bool
	credentials     interface{}
	principal       interface{}
	user            user.User
}

var _ credential.Credential = (*BadCredential)(nil)

// GetCredentials that prove the principal is correct, this is usually a password.
func (a *BadCredential) GetCredentials() interface{} {
	return a.credentials
}

// GetPrincipal The identity of the principal being authenticated.
// In the case of an authentication request with username and password,
// this would be the username.
func (a *BadCredential) GetPrincipal() interface{} {
	return a.principal
}

// IsAuthenticated returns true if token is authenticated.
func (a *BadCredential) IsAuthenticated() bool {
	return a.isAuthenticated
}

// SetAuthenticated change token to authenticated.
func (a *BadCredential) SetAuthenticated(isAuthenticated bool) {
	a.isAuthenticated = isAuthenticated
}

// SetUser set user authenticated.
func (a *BadCredential) SetUser(user user.User) {
	a.user = user
}

// GetUser return authenticated.
func (a *BadCredential) GetUser() user.User {
	return a.user
}

func TestOAuth2AuthenticationProviderIsSupported(t *testing.T) {
	p := &OAuth2AuthenticationProvider{}

	{
		creds := &credential.TokenCredential{}

		assert.True(t, p.IsSupported(creds))
	}

	{
		creds := &credential.UsernamePasswordCredential{}

		assert.True(t, p.IsSupported(creds))
	}

	{
		creds := &BadCredential{}

		assert.False(t, p.IsSupported(creds))
	}
}
