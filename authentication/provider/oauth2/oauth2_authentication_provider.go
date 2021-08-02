// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/hyperscale-stack/security/authentication"
	"github.com/hyperscale-stack/security/authentication/credential"
	"github.com/hyperscale-stack/security/authentication/provider/oauth2/token"
	"github.com/hyperscale-stack/security/user"
)

var (
	ErrBadAuthenticationFormat = errors.New("bad authentication format")
	ErrTokenExpired            = errors.New("token expired")
)

// OAuth2AuthenticationProvider struct.
type OAuth2AuthenticationProvider struct {
	tokenGenerator token.Generator
	storage        Storage
}

var _ authentication.Provider = (*OAuth2AuthenticationProvider)(nil)

// NewOAuth2AuthenticationProvider constructor.
func NewOAuth2AuthenticationProvider(tokenGenerator token.Generator, storage Storage) *OAuth2AuthenticationProvider {
	return &OAuth2AuthenticationProvider{
		tokenGenerator: tokenGenerator,
		storage:        storage,
	}
}

// IsSupported returns true if credential.Credential is supported.
func (p *OAuth2AuthenticationProvider) IsSupported(creds credential.Credential) bool {
	//TODO multiple support (ClientCreds, etc...)

	switch creds.(type) {
	case *credential.TokenCredential, *credential.UsernamePasswordCredential:
		return true
	default:
		return false
	}
}

func (p *OAuth2AuthenticationProvider) authenticateByToken(r *http.Request, creds *credential.TokenCredential) error {
	token, err := p.storage.LoadAccess(creds.GetPrincipal().(string))
	if err != nil {
		return fmt.Errorf("load access token failed: %w", err)
	}

	if token.IsExpired() {
		return ErrTokenExpired
	}

	u := token.UserData.(user.User)

	creds.SetAuthenticated(true)
	creds.SetUser(u)

	return nil
}

func (p *OAuth2AuthenticationProvider) authenticateByClient(r *http.Request, creds *credential.UsernamePasswordCredential) error {
	_, err := p.storage.LoadClient(creds.GetPrincipal().(string))
	if err != nil {
		return fmt.Errorf("load client info failed: %w", err)
	}

	creds.SetAuthenticated(true)

	return nil
}

// Authenticate implements Provider.
func (p *OAuth2AuthenticationProvider) Authenticate(r *http.Request, creds credential.Credential) error {
	switch auth := creds.(type) {
	case *credential.TokenCredential:
		return p.authenticateByToken(r, auth)
	case *credential.UsernamePasswordCredential: //@TODO: use ClientCredential
		return p.authenticateByClient(r, auth)
	default:
		return ErrBadAuthenticationFormat
	}
}
