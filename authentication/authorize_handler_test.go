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
	"github.com/stretchr/testify/assert"
)

func TestAuthorizeHandler(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "OK")
	}

	req := httptest.NewRequest("GET", "http://example.com/v1/me", nil)
	req.Header.Set("Authorization", "Basic Zm9vOmJhcg==")

	w := httptest.NewRecorder()

	middleware := alice.New(
		FilterHandler(NewHTTPBasicFilter(), NewBearerFilter()),
		AuthorizeHandler(),
	)

	middleware.ThenFunc(handler).ServeHTTP(w, req)

	resp := w.Result()
	body, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, []byte("OK"), body)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func BenchmarkAuthorizeHandler(b *testing.B) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "OK")
	}

	req := httptest.NewRequest("GET", "http://example.com/v1/me", nil)
	req.Header.Set("Authorization", "Bearer foo")

	w := httptest.NewRecorder()

	middleware := alice.New(
		FilterHandler(NewHTTPBasicFilter(), NewBearerFilter()),
		AuthorizeHandler(),
	)

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		middleware.ThenFunc(handler).ServeHTTP(w, req)
	}
}
