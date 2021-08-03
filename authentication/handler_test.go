// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package authentication

import (
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gilcrest/alice"
	"github.com/hyperscale-stack/security/authentication/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestHandlerWithoutCredential(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		auth := credential.FromContext(r.Context())
		assert.Nil(t, auth)

		io.WriteString(w, "OK")
	}

	req := httptest.NewRequest("GET", "http://example.com/v1/me", nil)

	w := httptest.NewRecorder()

	authenticationProviderMock := &MockProvider{}

	middleware := alice.New(
		FilterHandler(NewHTTPBasicFilter(), NewBearerFilter()),
		Handler(authenticationProviderMock),
	)

	middleware.ThenFunc(handler).ServeHTTP(w, req)

	resp := w.Result()
	body, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, []byte("OK"), body)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	authenticationProviderMock.AssertNotCalled(t, "IsSupported")
	authenticationProviderMock.AssertNotCalled(t, "Authenticate")
}

func TestHandlerWithNotSupportedCredential(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		auth := credential.FromContext(r.Context())

		assert.IsType(t, &credential.UsernamePasswordCredential{}, auth)

		assert.False(t, auth.IsAuthenticated())

		io.WriteString(w, "OK")
	}

	req := httptest.NewRequest("GET", "http://example.com/v1/me", nil)
	req.Header.Set("Authorization", "Basic Zm9vOmJhcg==")

	w := httptest.NewRecorder()

	authenticationProviderMock := &MockProvider{}

	authenticationProviderMock.On("IsSupported", mock.AnythingOfType("*credential.UsernamePasswordCredential")).Return(false).Once()

	middleware := alice.New(
		FilterHandler(NewHTTPBasicFilter(), NewBearerFilter()),
		Handler(authenticationProviderMock),
	)

	middleware.ThenFunc(handler).ServeHTTP(w, req)

	resp := w.Result()
	body, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, []byte("OK"), body)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	authenticationProviderMock.AssertExpectations(t)
	authenticationProviderMock.AssertNotCalled(t, "Authenticate")
}

func TestHandlerWithBadAuthorizationBasic(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "OK")
	}

	req := httptest.NewRequest("GET", "http://example.com/v1/me", nil)
	req.Header.Set("Authorization", "Basic Zm9vOmJhcg==")

	w := httptest.NewRecorder()

	authenticationProviderMock := &MockProvider{}

	authenticationProviderMock.On("Authenticate", mock.AnythingOfType("*http.Request"), mock.MatchedBy(func(c credential.Credential) bool {
		if c.GetPrincipal().(string) != "foo" {
			return false
		}

		if c.GetCredentials().(string) != "bar" {
			return false
		}

		c.SetAuthenticated(false)

		return true
	})).Return(req, errors.New("fail"))

	authenticationProviderMock.On("IsSupported", mock.AnythingOfType("*credential.UsernamePasswordCredential")).Return(true)

	middleware := alice.New(
		FilterHandler(NewHTTPBasicFilter(), NewBearerFilter()),
		Handler(authenticationProviderMock),
	)

	middleware.ThenFunc(handler).ServeHTTP(w, req)

	resp := w.Result()
	body, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, []byte("Access denied\n"), body)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	authenticationProviderMock.AssertExpectations(t)
}

func TestHandlerWithAuthorizationBasic(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		auth := credential.FromContext(r.Context())

		assert.IsType(t, &credential.UsernamePasswordCredential{}, auth)

		assert.True(t, auth.IsAuthenticated())

		io.WriteString(w, "OK")
	}

	req := httptest.NewRequest("GET", "http://example.com/v1/me", nil)
	req.Header.Set("Authorization", "Basic Zm9vOmJhcg==")

	ctx := req.Context()

	creds := credential.NewUsernamePasswordCredential("foo", "bar")

	creds.SetAuthenticated(true)

	ctx = credential.ToContext(ctx, creds)

	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	authenticationProviderMock := &MockProvider{}

	authenticationProviderMock.On("Authenticate", mock.AnythingOfType("*http.Request"), mock.MatchedBy(func(c credential.Credential) bool {
		if c.GetPrincipal().(string) != "foo" {
			return false
		}

		if c.GetCredentials().(string) != "bar" {
			return false
		}

		c.SetAuthenticated(true)

		return true
	})).Return(req, nil)

	authenticationProviderMock.On("IsSupported", mock.AnythingOfType("*credential.UsernamePasswordCredential")).Return(true)

	middleware := alice.New(
		FilterHandler(NewHTTPBasicFilter(), NewBearerFilter()),
		Handler(authenticationProviderMock),
	)

	middleware.ThenFunc(handler).ServeHTTP(w, req)

	resp := w.Result()
	body, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, []byte("OK"), body)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	authenticationProviderMock.AssertExpectations(t)
}

type TestAuthenticationProvider struct{}

func (p *TestAuthenticationProvider) Authenticate(r *http.Request, creds credential.Credential) (*http.Request, error) {
	return r, nil
}

func (p *TestAuthenticationProvider) IsSupported(creds credential.Credential) bool {
	return true
}

func BenchmarkHandler(b *testing.B) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "OK")
	}

	req := httptest.NewRequest("GET", "http://example.com/v1/me", nil)
	req.Header.Set("Authorization", "Bearer foo")

	w := httptest.NewRecorder()

	authenticationProviderMock := &TestAuthenticationProvider{}

	middleware := alice.New(
		FilterHandler(NewHTTPBasicFilter(), NewBearerFilter()),
		Handler(authenticationProviderMock),
	)

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		middleware.ThenFunc(handler).ServeHTTP(w, req)
	}
}
