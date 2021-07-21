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

func TestAccessTokenFilter(t *testing.T) {
	f := NewAccessTokenFilter()

	r := httptest.NewRequest(http.MethodGet, "/path?access_token=foo", nil)

	r = f.OnFilter(r)

	auth := credential.FromContext(r.Context())

	assert.IsType(t, &credential.TokenCredential{}, auth)
	assert.Equal(t, "foo", auth.GetPrincipal())
}

func TestAccessTokenFilterWithoutAccessTokenInQueryString(t *testing.T) {
	f := NewAccessTokenFilter()

	r := httptest.NewRequest(http.MethodGet, "/path", nil)

	r = f.OnFilter(r)

	auth := credential.FromContext(r.Context())
	assert.Nil(t, auth)
}

func TestAccessTokenFilterWithEmptyAccessTokenInQueryString(t *testing.T) {
	f := NewAccessTokenFilter()

	r := httptest.NewRequest(http.MethodGet, "/path?access_token=", nil)

	r = f.OnFilter(r)

	auth := credential.FromContext(r.Context())
	assert.Nil(t, auth)
}

func BenchmarkAccessTokenFilter(b *testing.B) {
	f := NewAccessTokenFilter()

	r := httptest.NewRequest(http.MethodGet, "/path?access_token=foo", nil)

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		r = f.OnFilter(r)
	}
}
