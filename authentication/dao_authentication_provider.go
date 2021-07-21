// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package authentication

import (
	"fmt"

	"github.com/hyperscale-stack/security/authentication/credential"
	"github.com/hyperscale-stack/security/password"
	"github.com/hyperscale-stack/security/user"
)

// DaoAuthenticationProvider struct.
type DaoAuthenticationProvider struct {
	passwordHasher password.Hasher
	userProvider   UserProvider
}

var _ Provider = (*DaoAuthenticationProvider)(nil)

// NewDaoAuthenticationProvider constructor.
func NewDaoAuthenticationProvider(passwordHasher password.Hasher, userProvider UserProvider) *DaoAuthenticationProvider {
	return &DaoAuthenticationProvider{
		passwordHasher: passwordHasher,
		userProvider:   userProvider,
	}
}

// IsSupported returns true if credential.Credential is supported.
func (p *DaoAuthenticationProvider) IsSupported(authentication credential.Credential) bool {
	_, ok := authentication.(*credential.UsernamePasswordCredential)

	return ok
}

// Authenticate implements Provider.
func (p *DaoAuthenticationProvider) Authenticate(creds credential.Credential) error {
	auth, ok := creds.(*credential.UsernamePasswordCredential)
	if !ok {
		return ErrBadAuthenticationFormat
	}

	u, err := p.userProvider.LoadUserByUsername(auth.GetPrincipal().(string))
	if err != nil {
		return fmt.Errorf("user provider failed: %w", err)
	}

	userPassword, ok := auth.GetCredentials().(string)
	if !ok {
		return ErrCredentialsMustStringType
	}

	if us, ok := interface{}(u).(user.PasswordSalt); ok {
		userPassword = us.SaltPassword(userPassword, us.GetSalt())
	}

	if !p.passwordHasher.Verify(u.GetPassword(), userPassword) {
		return ErrBadPassword
	}

	creds.SetAuthenticated(true)
	creds.SetUser(u)

	return nil
}
