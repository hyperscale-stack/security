// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package authorization

import (
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gilcrest/alice"
	"github.com/hyperscale-stack/security/authentication"
	"github.com/hyperscale-stack/security/authentication/credential"
	"github.com/hyperscale-stack/security/user"
	"github.com/stretchr/testify/assert"
)

type TestAuthenticationProvider struct {
	authenticated bool
	user          user.User
}

func (p *TestAuthenticationProvider) Authenticate(r *http.Request, creds credential.Credential) error {
	creds.SetAuthenticated(p.authenticated)

	if p.user != nil {
		creds.SetUser(p.user)
	}

	return nil
}

func (p *TestAuthenticationProvider) IsSupported(creds credential.Credential) bool {
	return true
}

func TestAuthorizeHandlerWithoutCredential(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "OK")
	}

	req := httptest.NewRequest("GET", "http://example.com/v1/me", nil)

	w := httptest.NewRecorder()

	middleware := alice.New(
		authentication.FilterHandler(authentication.NewHTTPBasicFilter(), authentication.NewBearerFilter()),
		authentication.Handler(&TestAuthenticationProvider{}),
		AuthorizeHandler(),
	)

	middleware.ThenFunc(handler).ServeHTTP(w, req)

	resp := w.Result()
	body, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, []byte("Access denied\n"), body)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAuthorizeHandlerWithBadCredential(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "OK")
	}

	req := httptest.NewRequest("GET", "http://example.com/v1/me", nil)
	req.Header.Set("Authorization", "Basic Zm9vOmJhcg==")

	w := httptest.NewRecorder()

	middleware := alice.New(
		authentication.FilterHandler(authentication.NewHTTPBasicFilter(), authentication.NewBearerFilter()),
		authentication.Handler(&TestAuthenticationProvider{authenticated: false}),
		AuthorizeHandler(),
	)

	middleware.ThenFunc(handler).ServeHTTP(w, req)

	resp := w.Result()
	body, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, []byte("Access denied\n"), body)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAuthorizeHandler(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "OK")
	}

	req := httptest.NewRequest("GET", "http://example.com/v1/me", nil)
	req.Header.Set("Authorization", "Basic Zm9vOmJhcg==")

	w := httptest.NewRecorder()

	middleware := alice.New(
		authentication.FilterHandler(authentication.NewHTTPBasicFilter(), authentication.NewBearerFilter()),
		authentication.Handler(&TestAuthenticationProvider{authenticated: true}),
		AuthorizeHandler(),
	)

	middleware.ThenFunc(handler).ServeHTTP(w, req)

	resp := w.Result()
	body, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, []byte("OK"), body)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestAuthorizeHandlerWithBadHasRole(t *testing.T) {
	userMock := &user.MockUser{}

	userMock.On("GetRoles").Return([]string{"ROLE_USER"})

	handler := func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "OK")
	}

	req := httptest.NewRequest("GET", "http://example.com/v1/me", nil)
	req.Header.Set("Authorization", "Basic Zm9vOmJhcg==")

	w := httptest.NewRecorder()

	middleware := alice.New(
		authentication.FilterHandler(authentication.NewHTTPBasicFilter(), authentication.NewBearerFilter()),
		authentication.Handler(&TestAuthenticationProvider{authenticated: true, user: userMock}),
		AuthorizeHandler(HasRole("ROLE_ADMIN")),
	)

	middleware.ThenFunc(handler).ServeHTTP(w, req)

	resp := w.Result()
	body, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, []byte("Access denied\n"), body)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	userMock.AssertExpectations(t)
}

func TestAuthorizeHandlerWithHasRole(t *testing.T) {
	userMock := &user.MockUser{}

	userMock.On("GetRoles").Return([]string{"ROLE_ADMIN", "ROLE_USER"})

	handler := func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "OK")
	}

	req := httptest.NewRequest("GET", "http://example.com/v1/me", nil)
	req.Header.Set("Authorization", "Basic Zm9vOmJhcg==")

	w := httptest.NewRecorder()

	middleware := alice.New(
		authentication.FilterHandler(authentication.NewHTTPBasicFilter(), authentication.NewBearerFilter()),
		authentication.Handler(&TestAuthenticationProvider{authenticated: true, user: userMock}),
		AuthorizeHandler(HasRole("ROLE_ADMIN")),
	)

	middleware.ThenFunc(handler).ServeHTTP(w, req)

	resp := w.Result()
	body, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, []byte("OK"), body)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	userMock.AssertExpectations(t)
}

func BenchmarkAuthorizeHandler(b *testing.B) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "OK")
	}

	req := httptest.NewRequest("GET", "http://example.com/v1/me", nil)
	req.Header.Set("Authorization", "Bearer foo")

	w := httptest.NewRecorder()

	middleware := alice.New(
		authentication.FilterHandler(authentication.NewHTTPBasicFilter(), authentication.NewBearerFilter()),
		AuthorizeHandler(),
	)

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		middleware.ThenFunc(handler).ServeHTTP(w, req)
	}
}
