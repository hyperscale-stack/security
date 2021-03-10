// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package authentication

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBearerFilter(t *testing.T) {
	f := NewBearerFilter()

	r := httptest.NewRequest(http.MethodGet, "/path", nil)
	r.Header.Set("Authorization", "Bearer foo")

	r = f.OnFilter(r)

	auth := FromContext(r.Context())

	assert.IsType(t, &TokenAuthentication{}, auth)
}

func TestBearerFilterWithoutAuthorizationHeader(t *testing.T) {
	f := NewBearerFilter()

	r := httptest.NewRequest(http.MethodGet, "/path", nil)

	r = f.OnFilter(r)

	auth := FromContext(r.Context())
	assert.Nil(t, auth)
}

func TestBearerFilterWithBadAuthorizationType(t *testing.T) {
	f := NewBearerFilter()

	r := httptest.NewRequest(http.MethodGet, "/path", nil)
	r.Header.Set("Authorization", "Basic Zm9vOnBhc3M=")

	r = f.OnFilter(r)

	auth := FromContext(r.Context())
	assert.Nil(t, auth)
}

func BenchmarkBearerFilter(b *testing.B) {
	f := NewBearerFilter()

	r := httptest.NewRequest(http.MethodGet, "/path", nil)
	r.Header.Set("Authorization", "Bearer foo")

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		r = f.OnFilter(r)
	}
}
