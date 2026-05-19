// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/authentication"
	"github.com/hyperscale-stack/security/authentication/credential"
	"github.com/hyperscale-stack/security/authentication/provider/oauth2/token"
)

var (
	ErrBadAuthenticationFormat = errors.New("bad authentication format")
	// ErrTokenExpired is the local alias for security.ErrTokenExpired. It is
	// kept exported for backward compatibility; new code SHOULD compare against
	// security.ErrTokenExpired via errors.Is — both work transparently.
	ErrTokenExpired       = fmt.Errorf("oauth2: %w", security.ErrTokenExpired)
	ErrBadTypeForUserData = errors.New("bad type for user data")
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

//nolint:staticcheck // legacy package, scheduled removal Phase 7
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
//
//nolint:staticcheck // legacy package, scheduled removal Phase 7
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

	matcher, ok := client.(ClientSecretMatcher)
	if !ok {
		// A client that cannot verify its own secret cannot be authenticated
		// with the client_credentials grant. Surface it as a security error
		// instead of silently leaving the credential unauthenticated.
		return r, fmt.Errorf("oauth2: client %q does not implement ClientSecretMatcher: %w",
			client.GetID(), security.ErrClientSecretMismatch)
	}

	// nolint:forcetypeassert
	if !matcher.SecretMatches(creds.GetCredentials().(string)) {
		return r, fmt.Errorf("oauth2: client %q: %w", client.GetID(), security.ErrClientSecretMismatch)
	}

	creds.SetAuthenticated(true)

	ctx = ClientToContext(ctx, client)

	return r.WithContext(ctx), nil
}

// Authenticate implements Provider.
//
//nolint:staticcheck // legacy package, scheduled removal Phase 7
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
