// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package authentication

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hyperscale-stack/security/authentication/credential"
	"github.com/stretchr/testify/assert"
)

func TestHTTPBasicFilter(t *testing.T) {
	f := NewHTTPBasicFilter()

	r := httptest.NewRequest(http.MethodGet, "/path", nil)
	r.Header.Set("Authorization", "Basic Zm9vOmJhcg==")

	r = f.OnFilter(r)

	auth := credential.FromContext(r.Context())

	assert.IsType(t, &credential.UsernamePasswordCredential{}, auth)
}

func TestHTTPBasicFilterWithoutAuthorizationHeader(t *testing.T) {
	f := NewHTTPBasicFilter()

	r := httptest.NewRequest(http.MethodGet, "/path", nil)

	r = f.OnFilter(r)

	auth := credential.FromContext(r.Context())
	assert.Nil(t, auth)
}

func TestHTTPBasicFilterWithBadAuthorizationType(t *testing.T) {
	f := NewHTTPBasicFilter()

	r := httptest.NewRequest(http.MethodGet, "/path", nil)
	r.Header.Set("Authorization", "Digest Zm9vOnBhc3M=")

	r = f.OnFilter(r)

	auth := credential.FromContext(r.Context())
	assert.Nil(t, auth)
}

func TestHTTPBasicFilterWithBadBase64(t *testing.T) {
	f := NewHTTPBasicFilter()

	r := httptest.NewRequest(http.MethodGet, "/path", nil)
	r.Header.Set("Authorization", "Basic YWJjZA=====")

	r = f.OnFilter(r)

	auth := credential.FromContext(r.Context())
	assert.Nil(t, auth)
}

func TestHTTPBasicFilterWithBadFormat(t *testing.T) {
	f := NewHTTPBasicFilter()

	r := httptest.NewRequest(http.MethodGet, "/path", nil)
	r.Header.Set("Authorization", "Basic Zm9v")

	r = f.OnFilter(r)

	auth := credential.FromContext(r.Context())
	assert.Nil(t, auth)
}

func BenchmarkHTTPBasicFilter(b *testing.B) {
	f := NewHTTPBasicFilter()

	r := httptest.NewRequest(http.MethodGet, "/path", nil)
	r.Header.Set("Authorization", "Basic Zm9vOmJhcg==")

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		r = f.OnFilter(r)
	}
}
