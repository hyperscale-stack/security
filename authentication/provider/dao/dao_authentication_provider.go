// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package dao

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/hyperscale-stack/security/authentication"
	"github.com/hyperscale-stack/security/authentication/credential"
	"github.com/hyperscale-stack/security/password"
	"github.com/hyperscale-stack/security/user"
)

var (
	ErrBadAuthenticationFormat   = errors.New("bad authentication format")
	ErrBadPassword               = errors.New("bad password")
	ErrCredentialsMustStringType = errors.New("credentials type must string type")
)

// DaoAuthenticationProvider struct.
type DaoAuthenticationProvider struct {
	passwordHasher password.Hasher
	userProvider   UserProvider
}

var _ authentication.Provider = (*DaoAuthenticationProvider)(nil)

// NewDaoAuthenticationProvider constructor.
func NewDaoAuthenticationProvider(passwordHasher password.Hasher, userProvider UserProvider) *DaoAuthenticationProvider {
	return &DaoAuthenticationProvider{
		passwordHasher: passwordHasher,
		userProvider:   userProvider,
	}
}

// IsSupported returns true if credential.Credential is supported.
func (p *DaoAuthenticationProvider) IsSupported(creds credential.Credential) bool {
	_, ok := creds.(*credential.UsernamePasswordCredential)

	return ok
}

// Authenticate implements Provider.
func (p *DaoAuthenticationProvider) Authenticate(r *http.Request, creds credential.Credential) (*http.Request, error) {
	auth, ok := creds.(*credential.UsernamePasswordCredential)
	if !ok {
		return r, ErrBadAuthenticationFormat
	}

	// nolint:forcetypeassert
	u, err := p.userProvider.LoadUserByUsername(auth.GetPrincipal().(string))
	if err != nil {
		return r, fmt.Errorf("user provider failed: %w", err)
	}

	//nolint:forcetypeassert
	userPassword := auth.GetCredentials().(string)

	if us, ok := interface{}(u).(user.PasswordSalt); ok {
		userPassword = us.SaltPassword(userPassword, us.GetSalt())
	}

	if !p.passwordHasher.Verify(u.GetPassword(), userPassword) {
		return r, ErrBadPassword
	}

	creds.SetAuthenticated(true)
	creds.SetUser(u)

	return r, nil
}
