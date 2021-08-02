// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/authentication/credential"
	"github.com/hyperscale-stack/security/authentication/provider/oauth2/token/random"
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

func TestOAuth2AuthenticationProviderAuthenticateByClient(t *testing.T) {
	tokenGenerator := random.NewTokenGenerator(&random.Configuration{})

	storageMock := &MockStorage{}

	client := &DefaultClient{
		ID:          "5cc06c3b-5755-4229-958c-a515a245aaeb",
		Secret:      "WTvuAztPD2XBauomleRzGFYuZawS07Ym",
		RedirectURI: "https://connect.myservice.tld",
	}

	storageMock.On("LoadClient", "5cc06c3b-5755-4229-958c-a515a245aaeb").Return(client, nil)

	p := NewOAuth2AuthenticationProvider(tokenGenerator, storageMock)

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)

	creds := credential.NewUsernamePasswordCredential("5cc06c3b-5755-4229-958c-a515a245aaeb", "WTvuAztPD2XBauomleRzGFYuZawS07Ym")

	err := p.Authenticate(req, creds)
	assert.NoError(t, err)

	storageMock.AssertExpectations(t)
}

func TestOAuth2AuthenticationProviderAuthenticateByClientWithClientNotFound(t *testing.T) {
	tokenGenerator := random.NewTokenGenerator(&random.Configuration{})

	storageMock := &MockStorage{}

	storageMock.On("LoadClient", "bad").Return(nil, ErrClientNotFound)

	p := NewOAuth2AuthenticationProvider(tokenGenerator, storageMock)

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)

	creds := credential.NewUsernamePasswordCredential("bad", "bad")

	err := p.Authenticate(req, creds)
	assert.EqualError(t, err, "load client info failed: oauth2 client not found")

	storageMock.AssertExpectations(t)
}

func TestOAuth2AuthenticationProviderAuthenticateByAccessTokenWithTokenNotFound(t *testing.T) {
	tokenGenerator := random.NewTokenGenerator(&random.Configuration{})

	storageMock := &MockStorage{}

	storageMock.On("LoadAccess", "bad").Return(nil, ErrAccessNotFound)

	p := NewOAuth2AuthenticationProvider(tokenGenerator, storageMock)

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)

	creds := credential.NewTokenCredential("bad")

	err := p.Authenticate(req, creds)
	assert.EqualError(t, err, "load access token failed: oauth2 access token not found")

	storageMock.AssertExpectations(t)
}

func TestOAuth2AuthenticationProviderAuthenticateByAccessTokenWithTokenExpired(t *testing.T) {
	tokenGenerator := random.NewTokenGenerator(&random.Configuration{})

	userMock := &user.MockUser{}

	storageMock := &MockStorage{}

	access := &AccessInfo{
		AccessToken: "wSxJOjDWo7qQ7kF5Tlg2l9XZYat6gq6GssF5D5I9aKtcEipJzoTba77vRhfscn1vNr0gBM9rSj5sZ3R6252FTlJpxWPUM1c8w2KkvaAAcyrWqNPVNNFX2qAxhpcatdbR",
		ExpiresIn:   60,
		UserData:    userMock,
	}

	storageMock.On("LoadAccess", "wSxJOjDWo7qQ7kF5Tlg2l9XZYat6gq6GssF5D5I9aKtcEipJzoTba77vRhfscn1vNr0gBM9rSj5sZ3R6252FTlJpxWPUM1c8w2KkvaAAcyrWqNPVNNFX2qAxhpcatdbR").Return(access, nil)

	p := NewOAuth2AuthenticationProvider(tokenGenerator, storageMock)

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)

	creds := credential.NewTokenCredential("wSxJOjDWo7qQ7kF5Tlg2l9XZYat6gq6GssF5D5I9aKtcEipJzoTba77vRhfscn1vNr0gBM9rSj5sZ3R6252FTlJpxWPUM1c8w2KkvaAAcyrWqNPVNNFX2qAxhpcatdbR")

	err := p.Authenticate(req, creds)
	assert.EqualError(t, err, "token expired")

	storageMock.AssertExpectations(t)
}

func TestOAuth2AuthenticationProviderAuthenticateByAccessTokenWithToken(t *testing.T) {
	tokenGenerator := random.NewTokenGenerator(&random.Configuration{})

	userMock := &user.MockUser{}

	storageMock := &MockStorage{}

	access := &AccessInfo{
		AccessToken: "wSxJOjDWo7qQ7kF5Tlg2l9XZYat6gq6GssF5D5I9aKtcEipJzoTba77vRhfscn1vNr0gBM9rSj5sZ3R6252FTlJpxWPUM1c8w2KkvaAAcyrWqNPVNNFX2qAxhpcatdbR",
		ExpiresIn:   60,
		CreatedAt:   time.Now(),
		UserData:    userMock,
	}

	storageMock.On("LoadAccess", "wSxJOjDWo7qQ7kF5Tlg2l9XZYat6gq6GssF5D5I9aKtcEipJzoTba77vRhfscn1vNr0gBM9rSj5sZ3R6252FTlJpxWPUM1c8w2KkvaAAcyrWqNPVNNFX2qAxhpcatdbR").Return(access, nil)

	p := NewOAuth2AuthenticationProvider(tokenGenerator, storageMock)

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)

	creds := credential.NewTokenCredential("wSxJOjDWo7qQ7kF5Tlg2l9XZYat6gq6GssF5D5I9aKtcEipJzoTba77vRhfscn1vNr0gBM9rSj5sZ3R6252FTlJpxWPUM1c8w2KkvaAAcyrWqNPVNNFX2qAxhpcatdbR")

	err := p.Authenticate(req, creds)
	assert.NoError(t, err)

	storageMock.AssertExpectations(t)
}

func TestOAuth2AuthenticationProviderAuthenticateWithBadCredentialType(t *testing.T) {
	creds := &BadCredential{}

	p := NewOAuth2AuthenticationProvider(nil, nil)

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)

	err := p.Authenticate(req, creds)

	assert.EqualError(t, err, "bad authentication format")
}
