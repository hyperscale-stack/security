// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package authentication

import (
	"errors"
	"fmt"

	"github.com/hyperscale-stack/security/password"
)

// DaoProvider struct
type DaoProvider struct {
	passwordHasher password.Hasher
	userProvider   UserProvider
}

var _ Provider = (*DaoProvider)(nil)

// NewDaoProvider constructor
func NewDaoProvider(passwordHasher password.Hasher, userProvider UserProvider) *DaoProvider {
	return &DaoProvider{
		passwordHasher: passwordHasher,
		userProvider:   userProvider,
	}
}

// IsSupported returns true if Authentication is supported
func (p *DaoProvider) IsSupported(authentication Authentication) bool {
	_, ok := authentication.(*UsernamePasswordAuthentication)

	return ok
}

// Authenticate implements Provider
func (p *DaoProvider) Authenticate(authentication Authentication) (Authentication, error) {
	auth, ok := authentication.(*UsernamePasswordAuthentication)
	if !ok {
		return authentication, errors.New("bad authentication format")
	}

	user, err := p.userProvider.LoadUserByUsername(auth.GetPrincipal().(string))
	if err != nil {
		return authentication, fmt.Errorf("user provider failed: %w", err)
	}

	userPassword := auth.GetCredentials().(string)

	if us, ok := interface{}(user).(PasswordSalt); ok {
		userPassword = us.SaltPassword(userPassword, us.GetSalt())
	}

	if !p.passwordHasher.Verify(user.GetPassword(), userPassword) {
		return authentication, errors.New("bad password")
	}

	authentication.SetAuthenticated(true)

	return authentication, nil
}
