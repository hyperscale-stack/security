// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package authentication

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/hyperscale-stack/security/password"
)

// DaoProvider struct
type DaoProvider struct {
	passwordEncoder password.Encoder
	userProvider    UserProvider
}

var _ Provider = (*DaoProvider)(nil)

// NewDaoProvider constructor
func NewDaoProvider(passwordEncoder password.Encoder, userProvider UserProvider) *DaoProvider {
	return &DaoProvider{
		passwordEncoder: passwordEncoder,
		userProvider:    userProvider,
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

	hash, err := p.passwordEncoder.Encode(auth.GetCredentials().(string))
	if err != nil {
		return authentication, fmt.Errorf("password encoder failed: %w", err)
	}

	if !reflect.DeepEqual(user.GetPassword(), hash) {
		return authentication, errors.New("bad password")
	}

	authentication.SetAuthenticated(true)

	return authentication, nil
}
