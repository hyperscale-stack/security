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
)

var (
	ErrBadAuthenticationFormat = errors.New("bad authentication format")
	ErrTokenExpired            = errors.New("token expired")
	ErrBadTypeForUserData      = errors.New("bad type for user data")
)

// OAuth2AuthenticationProvider struct.
type OAuth2AuthenticationProvider struct {
	tokenGenerator   token.Generator
	userStorage      UserProvider
	clientStorage    ClientProvider
	accessStorage    AccessProvider
	refreshStorage   RefreshProvider
	authorizeStorage AuthorizeProvider
}

var _ authentication.Provider = (*OAuth2AuthenticationProvider)(nil)

// NewOAuth2AuthenticationProvider constructor.
func NewOAuth2AuthenticationProvider(
	tokenGenerator token.Generator,
	userStorage UserProvider,
	clientStorage ClientProvider,
	accessStorage AccessProvider,
	refreshStorage RefreshProvider,
	authorizeStorage AuthorizeProvider,
) *OAuth2AuthenticationProvider {
	return &OAuth2AuthenticationProvider{
		userStorage:      userStorage,
		tokenGenerator:   tokenGenerator,
		clientStorage:    clientStorage,
		accessStorage:    accessStorage,
		refreshStorage:   refreshStorage,
		authorizeStorage: authorizeStorage,
	}
}

// IsSupported returns true if credential.Credential is supported.
func (p *OAuth2AuthenticationProvider) IsSupported(creds credential.Credential) bool {
	// TODO multiple support (ClientCreds, etc...)
	switch creds.(type) {
	case *credential.TokenCredential, *credential.UsernamePasswordCredential:
		return true
	default:
		return false
	}
}

func (p *OAuth2AuthenticationProvider) authenticateByToken(r *http.Request, creds *credential.TokenCredential) (*http.Request, error) {
	ctx := r.Context()

	token, err := p.accessStorage.LoadAccess(creds.GetPrincipal().(string)) // nolint:forcetypeassert
	if err != nil {
		return r, fmt.Errorf("load access token failed: %w", err)
	}

	if token.IsExpired() {
		return r, ErrTokenExpired
	}

	userID, ok := token.UserData.(string)
	if !ok {
		return r, ErrBadTypeForUserData
	}

	u, err := p.userStorage.LoadUser(userID)
	if err != nil {
		return r, fmt.Errorf("load user failed: %w", err)
	}

	creds.SetAuthenticated(true)
	creds.SetUser(u)

	ctx = AccessTokenToContext(ctx, token)
	ctx = ClientToContext(ctx, token.Client)

	return r.WithContext(ctx), nil
}

func (p *OAuth2AuthenticationProvider) authenticateByClient(r *http.Request, creds *credential.UsernamePasswordCredential) (*http.Request, error) {
	ctx := r.Context()

	client, err := p.clientStorage.LoadClient(creds.GetPrincipal().(string)) // nolint:forcetypeassert
	if err != nil {
		return r, fmt.Errorf("load client info failed: %w", err)
	}

	if c, ok := client.(ClientSecretMatcher); ok {
		// nolint:forcetypeassert
		if c.SecretMatches(creds.GetCredentials().(string)) {
			creds.SetAuthenticated(true)
		}
	}

	ctx = ClientToContext(ctx, client)

	return r.WithContext(ctx), nil
}

// Authenticate implements Provider.
func (p *OAuth2AuthenticationProvider) Authenticate(r *http.Request, creds credential.Credential) (*http.Request, error) {
	switch auth := creds.(type) {
	case *credential.TokenCredential:
		return p.authenticateByToken(r, auth)
	case *credential.UsernamePasswordCredential: // @TODO: use ClientCredential
		return p.authenticateByClient(r, auth)
	default:
		return r, ErrBadAuthenticationFormat
	}
}
