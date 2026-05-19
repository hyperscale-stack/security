// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package httpsec_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	httpsec "github.com/hyperscale-stack/security/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCarrierLookupOrderIsHeaderThenCookieThenQuery(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/?Authorization=q", nil)
	req.Header.Set("Authorization", "h")
	req.AddCookie(&http.Cookie{Name: "Authorization", Value: "c"})

	c := httpsec.NewCarrier(httptest.NewRecorder(), req)
	assert.Equal(t, "h", c.Get("Authorization"), "header wins")

	// Drop header -> cookie wins
	req.Header.Del("Authorization")
	c = httpsec.NewCarrier(httptest.NewRecorder(), req)
	assert.Equal(t, "c", c.Get("Authorization"))

	// Drop cookie too -> query wins
	req2 := httptest.NewRequest(http.MethodGet, "/?Authorization=q", nil)
	c = httpsec.NewCarrier(httptest.NewRecorder(), req2)
	assert.Equal(t, "q", c.Get("Authorization"))
}

func TestCarrierValuesPrefersHeaderMultiValues(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/?X-Foo=q1&X-Foo=q2", nil)
	req.Header.Add("X-Foo", "h1")
	req.Header.Add("X-Foo", "h2")

	c := httpsec.NewCarrier(httptest.NewRecorder(), req)
	assert.Equal(t, []string{"h1", "h2"}, c.Values("X-Foo"))
}

func TestCarrierSetWritesToResponseHeader(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	c := httpsec.NewCarrier(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	c.Set("WWW-Authenticate", "Bearer")
	c.Add("WWW-Authenticate", "Basic")

	require.Equal(t, []string{"Bearer", "Basic"}, rec.Header().Values("WWW-Authenticate"))
}

func TestCarrierWithNilRequestAndWriterIsSafe(t *testing.T) {
	t.Parallel()

	c := httpsec.NewCarrier(nil, nil)

	assert.Equal(t, "", c.Get("anything"))
	assert.Nil(t, c.Values("anything"))
	c.Set("X", "Y") // must not panic
	c.Add("X", "Y") // must not panic
}

func TestCarrierExposesUnderlyingRequest(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	c := httpsec.NewCarrier(httptest.NewRecorder(), req)
	assert.Same(t, req, c.Request())
}

func TestExtractAuthorizationValueIsCaseInsensitive(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, scheme, header, want string
		ok                         bool
	}{
		{"bearer_lower", "Bearer", "bearer abc", "abc", true},
		{"bearer_upper", "Bearer", "BEARER abc", "abc", true},
		{"basic", "Basic", "Basic Zm9vOmJhcg==", "Zm9vOmJhcg==", true},
		{"wrong_scheme", "Basic", "Bearer xyz", "", false},
		{"too_short", "Bearer", "Bea", "", false},
		{"empty", "Bearer", "", "", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			got, ok := httpsec.ExtractAuthorizationValue(c.scheme, c.header)
			assert.Equal(t, c.want, got)
			assert.Equal(t, c.ok, ok)
		})
	}
}
