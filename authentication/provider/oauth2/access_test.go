// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/authentication/credential"
	"github.com/stretchr/testify/assert"
	mock "github.com/stretchr/testify/mock"
)

func TestAccessData(t *testing.T) {
	cat, err := time.Parse("2006-01-02T15:04:05.000Z", "2014-11-12T11:45:26.371Z")
	assert.NoError(t, err)

	ai := &AccessData{
		CreatedAt: cat,
		ExpiresIn: 10,
	}

	assert.True(t, ai.IsExpired())
}

func TestAccessTokenContext(t *testing.T) {
	ctx := context.Background()

	ai := &AccessData{
		CreatedAt: time.Now(),
		ExpiresIn: 10,
	}

	ctx = AccessTokenToContext(ctx, ai)

	ai2 := AccessTokenFromContext(ctx)

	assert.Equal(t, ai, ai2)
}

func TestFromContextWithEmptyContext(t *testing.T) {
	ctx := context.Background()

	ai := AccessTokenFromContext(ctx)
	assert.Nil(t, ai)
}

func TestServerHandleAccessRequestWithGetMethodNotAllowed(t *testing.T) {
	cfg := &Configuration{
		ErrorStatusCode:       http.StatusOK,
		AllowGetAccessRequest: false,
	}
	s := NewServer(WithConfig(cfg))

	w := s.NewResponse()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/v1/me", nil)

	ar := s.HandleAccessRequest(w, req)
	assert.Nil(t, ar)

	assert.Equal(t, E_INVALID_REQUEST, w.ErrorID)
}

func TestServerHandleAccessRequestWithBadMethod(t *testing.T) {
	cfg := &Configuration{
		ErrorStatusCode:       http.StatusOK,
		AllowGetAccessRequest: false,
	}
	s := NewServer(WithConfig(cfg))

	w := s.NewResponse()

	req := httptest.NewRequest(http.MethodPut, "http://example.com/v1/me", nil)

	ar := s.HandleAccessRequest(w, req)
	assert.Nil(t, ar)

	assert.Equal(t, E_INVALID_REQUEST, w.ErrorID)
}

type mockReadCloser struct {
	mock.Mock
}

func (m *mockReadCloser) Read(p []byte) (n int, err error) {
	args := m.Called(p)

	return args.Int(0), args.Error(1)
}

func (m *mockReadCloser) Close() error {
	args := m.Called()

	return args.Error(0)
}

func TestServerHandleAccessRequestWithBadBody(t *testing.T) {
	/*mockReadCloser := &mockReadCloser{}
	// if Read is called, it will return error
	mockReadCloser.On("Read", mock.AnythingOfType("[]uint8")).Return(0, fmt.Errorf("error reading"))
	// if Close is called, it will return error
	mockReadCloser.On("Close").Return(fmt.Errorf("error closing"))
	*/
	cfg := &Configuration{
		ErrorStatusCode:       http.StatusOK,
		AllowGetAccessRequest: false,
	}
	s := NewServer(WithConfig(cfg))

	w := s.NewResponse()

	req := httptest.NewRequest(http.MethodPost, "http://example.com/v1/me?f$$", nil)

	req.Body = nil

	ar := s.HandleAccessRequest(w, req)
	assert.Nil(t, ar)

	assert.Equal(t, E_INVALID_REQUEST, w.ErrorID)
}

func TestServerHandleAccessRequestWithEmptyBody(t *testing.T) {
	cfg := &Configuration{
		ErrorStatusCode:       http.StatusOK,
		AllowGetAccessRequest: false,
	}
	s := NewServer(WithConfig(cfg))

	w := s.NewResponse()

	req := httptest.NewRequest(http.MethodPost, "http://example.com/v1/me?f$$", nil)

	ar := s.HandleAccessRequest(w, req)
	assert.Nil(t, ar)

	assert.Equal(t, E_UNSUPPORTED_GRANT_TYPE, w.ErrorID)
}

func TestServerHandleAccessRequestWithPasswordGrandTypeWithInvalidRequest(t *testing.T) {
	cfg := &Configuration{
		ErrorStatusCode:       http.StatusOK,
		AllowGetAccessRequest: false,
		AllowedAccessTypes: AllowedAccessType{
			PASSWORD,
		},
	}
	s := NewServer(WithConfig(cfg))

	w := s.NewResponse()

	data := url.Values{}

	data.Set("grant_type", "password")

	req := httptest.NewRequest(http.MethodPost, "http://example.com/oauth/token", strings.NewReader(data.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))

	ar := s.HandleAccessRequest(w, req)
	assert.Nil(t, ar)

	assert.Equal(t, E_INVALID_REQUEST, w.ErrorID)
}

func TestServerGetClientWithErrClientNotFound(t *testing.T) {
	cfg := &Configuration{}
	storageMock := &MockStorageProvider{}

	storageMock.On("LoadClient", "9b48f589-735c-476c-aa5f-eae9e2422d01").Return(nil, ErrClientNotFound)

	s := NewServer(WithConfig(cfg), WithStorage(storageMock))

	w := s.NewResponse()

	creds := credential.NewUsernamePasswordCredential("9b48f589-735c-476c-aa5f-eae9e2422d01", "foo")

	c := s.getClient(creds, storageMock, w)
	assert.Nil(t, c)

	assert.Equal(t, E_UNAUTHORIZED_CLIENT, w.ErrorID)

	storageMock.AssertExpectations(t)
}

func TestServerGetClientWithErr(t *testing.T) {
	cfg := &Configuration{}
	storageMock := &MockStorageProvider{}

	storageMock.On("LoadClient", "9b48f589-735c-476c-aa5f-eae9e2422d01").Return(nil, errors.New("foo"))

	s := NewServer(WithConfig(cfg), WithStorage(storageMock))

	w := s.NewResponse()

	creds := credential.NewUsernamePasswordCredential("9b48f589-735c-476c-aa5f-eae9e2422d01", "foo")

	c := s.getClient(creds, storageMock, w)
	assert.Nil(t, c)

	assert.Equal(t, E_SERVER_ERROR, w.ErrorID)

	storageMock.AssertExpectations(t)
}

func TestServerGetClientWithClientEmpry(t *testing.T) {
	cfg := &Configuration{}
	storageMock := &MockStorageProvider{}

	storageMock.On("LoadClient", "9b48f589-735c-476c-aa5f-eae9e2422d01").Return(nil, nil)

	s := NewServer(WithConfig(cfg), WithStorage(storageMock))

	w := s.NewResponse()

	creds := credential.NewUsernamePasswordCredential("9b48f589-735c-476c-aa5f-eae9e2422d01", "foo")

	c := s.getClient(creds, storageMock, w)
	assert.Nil(t, c)

	assert.Equal(t, E_UNAUTHORIZED_CLIENT, w.ErrorID)

	storageMock.AssertExpectations(t)
}

func TestServerGetClientWithClientBadSecret(t *testing.T) {
	cfg := &Configuration{}
	storageMock := &MockStorageProvider{}

	client := &DefaultClient{
		Secret: "bar",
	}

	storageMock.On("LoadClient", "9b48f589-735c-476c-aa5f-eae9e2422d01").Return(client, nil)

	s := NewServer(WithConfig(cfg), WithStorage(storageMock))

	w := s.NewResponse()

	creds := credential.NewUsernamePasswordCredential("9b48f589-735c-476c-aa5f-eae9e2422d01", "foo")

	c := s.getClient(creds, storageMock, w)
	assert.Nil(t, c)

	assert.Equal(t, E_UNAUTHORIZED_CLIENT, w.ErrorID)

	storageMock.AssertExpectations(t)
}

func TestServerGetClientWithClientBadRedirect(t *testing.T) {
	cfg := &Configuration{}
	storageMock := &MockStorageProvider{}

	client := &DefaultClient{
		Secret:      "foo",
		RedirectURI: "",
	}

	storageMock.On("LoadClient", "9b48f589-735c-476c-aa5f-eae9e2422d01").Return(client, nil)

	s := NewServer(WithConfig(cfg), WithStorage(storageMock))

	w := s.NewResponse()

	creds := credential.NewUsernamePasswordCredential("9b48f589-735c-476c-aa5f-eae9e2422d01", "foo")

	c := s.getClient(creds, storageMock, w)
	assert.Nil(t, c)

	assert.Equal(t, E_UNAUTHORIZED_CLIENT, w.ErrorID)

	storageMock.AssertExpectations(t)
}

func TestServerGetClient(t *testing.T) {
	cfg := &Configuration{}
	storageMock := &MockStorageProvider{}

	client := &DefaultClient{
		Secret:      "foo",
		RedirectURI: "https://auth.mydomain.tld/connect",
	}

	storageMock.On("LoadClient", "9b48f589-735c-476c-aa5f-eae9e2422d01").Return(client, nil)

	s := NewServer(WithConfig(cfg), WithStorage(storageMock))

	w := s.NewResponse()

	creds := credential.NewUsernamePasswordCredential("9b48f589-735c-476c-aa5f-eae9e2422d01", "foo")

	c := s.getClient(creds, storageMock, w)
	assert.Same(t, client, c)

	storageMock.AssertExpectations(t)
}

func TestExtraScopes(t *testing.T) {
	assert.True(t, extraScopes("foo bar", "foo bar jar"))
	assert.False(t, extraScopes("foo bar", "foo bar"))

	assert.False(t, extraScopes(" ", " "))
}

func TestServerHandlePasswordRequestWithEmptyUsernameAndPassword(t *testing.T) {
	cfg := &Configuration{
		ErrorStatusCode:       http.StatusOK,
		AllowGetAccessRequest: false,
		AllowedAccessTypes: AllowedAccessType{
			PASSWORD,
		},
	}

	storageMock := &MockStorageProvider{}

	storageMock.On("LoadClient", "50542ad2-5983-4977-baab-ef3794f08c89").Return(nil, nil)

	s := NewServer(WithConfig(cfg), WithStorage(storageMock))

	w := s.NewResponse()
	/*
		data := url.Values{}

		data.Set("grant_type", "password")
		data.Set("username", "")
		data.Set("password", "")
	*/
	req := httptest.NewRequest(http.MethodPost, "http://example.com/oauth/token", nil)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	//req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))

	ctx := req.Context()
	ctx = credential.ToContext(ctx, credential.NewUsernamePasswordCredential("", ""))
	req = req.WithContext(ctx)

	ar := s.handlePasswordRequest(w, req)
	assert.Nil(t, ar)

	assert.Equal(t, E_INVALID_GRANT, w.ErrorID)
}

func TestServerHandlePasswordRequestWithClientNotFound(t *testing.T) {
	cfg := &Configuration{
		ErrorStatusCode:       http.StatusOK,
		AllowGetAccessRequest: false,
		AllowedAccessTypes: AllowedAccessType{
			PASSWORD,
		},
		RedirectURISeparator: " ",
	}

	storageMock := &MockStorageProvider{}

	storageMock.On("LoadClient", "50542ad2-5983-4977-baab-ef3794f08c89").Return(nil, ErrClientNotFound)

	s := NewServer(WithConfig(cfg), WithStorage(storageMock))

	w := s.NewResponse()

	data := url.Values{}

	data.Set("grant_type", "password")
	data.Set("username", "user@domain.com")
	data.Set("password", "passw0rd")

	req := httptest.NewRequest(http.MethodPost, "http://example.com/oauth/token", strings.NewReader(data.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	ctx := req.Context()
	ctx = credential.ToContext(ctx, credential.NewUsernamePasswordCredential("50542ad2-5983-4977-baab-ef3794f08c89", "mySecretPassw0rd!"))
	req = req.WithContext(ctx)

	ar := s.handlePasswordRequest(w, req)
	assert.Nil(t, ar)

	assert.Equal(t, E_UNAUTHORIZED_CLIENT, w.ErrorID)

	storageMock.AssertExpectations(t)
}

func TestServerHandlePasswordRequest(t *testing.T) {
	cfg := &Configuration{
		ErrorStatusCode:       http.StatusOK,
		AllowGetAccessRequest: false,
		AllowedAccessTypes: AllowedAccessType{
			PASSWORD,
		},
		RedirectURISeparator: " ",
	}

	storageMock := &MockStorageProvider{}

	client := &DefaultClient{
		ID:          "50542ad2-5983-4977-baab-ef3794f08c89",
		Secret:      "mySecretPassw0rd!",
		RedirectURI: "https://auth.mydomain.tld/connect",
	}

	storageMock.On("LoadClient", "50542ad2-5983-4977-baab-ef3794f08c89").Return(client, nil)

	s := NewServer(WithConfig(cfg), WithStorage(storageMock))

	w := s.NewResponse()

	data := url.Values{}

	data.Set("grant_type", "password")
	data.Set("username", "user@domain.com")
	data.Set("password", "passw0rd")

	req := httptest.NewRequest(http.MethodPost, "http://example.com/oauth/token", strings.NewReader(data.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	ctx := req.Context()
	ctx = credential.ToContext(ctx, credential.NewUsernamePasswordCredential("50542ad2-5983-4977-baab-ef3794f08c89", "mySecretPassw0rd!"))
	req = req.WithContext(ctx)

	ar := s.handlePasswordRequest(w, req)
	assert.NotNil(t, ar)

	assert.Same(t, client, ar.Client)

	storageMock.AssertExpectations(t)
}
