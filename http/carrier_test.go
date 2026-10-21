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

// Audit CORE-02 / decision 6: Get and Values fell back to a cookie and to
// the query string named like the key, so Basic and Bearer credentials were
// accepted from ?Authorization=… and from a cookie named Authorization.
func TestCarrierReadsHeaderFieldsOnly(t *testing.T) {
	t.Parallel()

	outsideHeaders := httptest.NewRequest(http.MethodGet, "/?Authorization=q", nil)
	outsideHeaders.AddCookie(&http.Cookie{Name: "Authorization", Value: "c"})

	c := httpsec.NewCarrier(httptest.NewRecorder(), outsideHeaders)
	assert.Empty(t, c.Get("Authorization"), "neither the query string nor a cookie is a header field")
	assert.Nil(t, c.Values("Authorization"))

	outsideHeaders.Header.Set("Authorization", "h")
	assert.Equal(t, "h", c.Get("Authorization"))
	assert.Equal(t, []string{"h"}, c.Values("Authorization"))
}

func TestCarrierValuesReturnsEveryHeaderValue(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/?X-Foo=q1&X-Foo=q2", nil)
	req.Header.Add("X-Foo", "h1")
	req.Header.Add("X-Foo", "h2")

	c := httpsec.NewCarrier(httptest.NewRecorder(), req)
	assert.Equal(t, []string{"h1", "h2"}, c.Values("X-Foo"))
	assert.Nil(t, c.Values("X-Bar"))
}

// The session module reads its cookie through this explicit accessor, never
// through Get or Values.
func TestCarrierCookiesNamedReadsTheCookieHeaderOnly(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/?session=from-query", nil)
	req.Header.Set("Session", "from-header")
	req.AddCookie(&http.Cookie{Name: "session", Value: "from-cookie"})
	req.AddCookie(&http.Cookie{Name: "other", Value: "x"})

	c := httpsec.NewCarrier(httptest.NewRecorder(), req)

	cookies := c.CookiesNamed("session")
	require.Len(t, cookies, 1)
	assert.Equal(t, "from-cookie", cookies[0].Value)
	assert.Empty(t, c.CookiesNamed("absent"))
}

// HTTP/2 lets a client split the Cookie field into several field lines
// (RFC 9113 §8.2.3): every line is read.
func TestCarrierCookiesNamedReadsSplitCookieFields(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Add("Cookie", "a=1")
	req.Header.Add("Cookie", "session=s; b=2")

	cookies := httpsec.NewCarrier(nil, req).CookiesNamed("session")
	require.Len(t, cookies, 1)
	assert.Equal(t, "s", cookies[0].Value)
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
	assert.Empty(t, c.CookiesNamed("anything"))
	c.Set("X", "Y") // must not panic
	c.Add("X", "Y") // must not panic
}

// Audit CORE-I3: Get panicked on a request without URL (fatal for a server
// without a recovery middleware).
func TestCarrierWithoutURLOrHeaderIsSafe(t *testing.T) {
	t.Parallel()

	c := httpsec.NewCarrier(httptest.NewRecorder(), &http.Request{})

	assert.NotPanics(t, func() {
		assert.Empty(t, c.Get("Authorization"))
		assert.Nil(t, c.Values("Authorization"))
		assert.Empty(t, c.CookiesNamed("session"))
	})
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
		// RFC 9110 §11.4: the scheme, then 1*SP (audit F-17).
		{"several_spaces", "Bearer", "Bearer   abc", "abc", true},
		{"scheme_alone", "Bearer", "Bearer", "", true},
		{"scheme_and_spaces", "Bearer", "Bearer  ", "", true},
		{"longer_scheme", "Bearer", "BearerX abc", "", false},
		{"tab_separator", "Bearer", "Bearer\tabc", "", false},
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
