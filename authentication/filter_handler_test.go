// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package authentication

import (
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gilcrest/alice"
	"github.com/hyperscale-stack/security/authentication/credential"
	"github.com/stretchr/testify/assert"
)

func TestFilterHandlerWithAuthorizationBasic(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		auth := credential.FromContext(r.Context())

		assert.IsType(t, &credential.UsernamePasswordCredential{}, auth)

		io.WriteString(w, "OK")
	}

	req := httptest.NewRequest("GET", "http://example.com/v1/me", nil)
	req.Header.Set("Authorization", "Basic Zm9vOmJhcg==")

	w := httptest.NewRecorder()

	middleware := alice.New(
		FilterHandler(NewHTTPBasicFilter(), NewBearerFilter()),
	)

	middleware.ThenFunc(handler).ServeHTTP(w, req)

	resp := w.Result()
	body, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, []byte("OK"), body)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestFilterHandlerWithAuthorizationBearer(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		auth := credential.FromContext(r.Context())

		assert.IsType(t, &credential.TokenCredential{}, auth)

		io.WriteString(w, "OK")
	}

	req := httptest.NewRequest("GET", "http://example.com/v1/me", nil)
	req.Header.Set("Authorization", "Bearer foo")

	w := httptest.NewRecorder()

	middleware := alice.New(
		FilterHandler(NewHTTPBasicFilter(), NewBearerFilter()),
	)

	middleware.ThenFunc(handler).ServeHTTP(w, req)

	resp := w.Result()
	body, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, []byte("OK"), body)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestFilterHandlerWithoutAuthorizationHeader(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		auth := credential.FromContext(r.Context())

		assert.Nil(t, auth)

		io.WriteString(w, "OK")
	}

	req := httptest.NewRequest("GET", "http://example.com/v1/me", nil)

	w := httptest.NewRecorder()

	middleware := alice.New(
		FilterHandler(NewHTTPBasicFilter(), NewBearerFilter()),
	)

	middleware.ThenFunc(handler).ServeHTTP(w, req)

	resp := w.Result()
	body, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, []byte("OK"), body)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func BenchmarkFilterHandler(b *testing.B) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "OK")
	}

	req := httptest.NewRequest("GET", "http://example.com/v1/me", nil)
	req.Header.Set("Authorization", "Bearer foo")

	w := httptest.NewRecorder()

	middleware := alice.New(
		FilterHandler(NewHTTPBasicFilter(), NewBearerFilter()),
	)

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		middleware.ThenFunc(handler).ServeHTTP(w, req)
	}
}
