// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package httpsec_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hyperscale-stack/security"
	httpsec "github.com/hyperscale-stack/security/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func anonymousMiddleware() func(http.Handler) http.Handler {
	return httpsec.Middleware(security.NewEngine(security.NewManager(), scriptedExtractor{}),
		httpsec.WithAnonymousFallback(true))
}

// Audit CORE-07 (probe TestZZAuditHTTPRouteIsRawPath): the span recorded the
// raw method — any client-chosen token — under the deprecated http.method.
func TestMiddlewareSpanNormalizesTheMethod(t *testing.T) {
	handler := anonymousMiddleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	for method, want := range map[string]string{
		"PROPFIND-XYZ":   "_OTHER",
		"get":            "_OTHER",
		http.MethodGet:   http.MethodGet,
		http.MethodPatch: http.MethodPatch,
		"QUERY":          "_OTHER",
	} {
		spans := recordSpans("httpsec.Middleware", func() {
			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(method, "/", nil))
		})

		require.Len(t, spans, 1, method)

		got, ok := spans[0].attr("http.request.method")
		assert.True(t, ok, method)
		assert.Equal(t, want, got, method)

		_, ok = spans[0].attr("http.method")
		assert.False(t, ok, "the deprecated http.method key is not emitted")
	}
}

// Audit CORE-07: http.route was the raw path — reset tokens and e-mail
// addresses in the path landed in the trace backend. It is now the mux
// pattern's path template, or absent.
func TestMiddlewareSpanRouteIsTheMuxPatternOrAbsent(t *testing.T) {
	const path = "/password-reset/9f2c1e7a-RESET-TOKEN/alice@example.com"

	inner := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})

	routed := http.NewServeMux()
	routed.Handle("GET /password-reset/{token}/{email}", anonymousMiddleware()(inner))

	wrapped := http.NewServeMux()
	wrapped.Handle("GET /password-reset/{token}/{email}", inner)

	cases := map[string]struct {
		handler http.Handler
		pattern string
		want    string
	}{
		"middleware inside the route": {routed, "", "/password-reset/{token}/{email}"},
		"middleware around the mux":   {anonymousMiddleware()(wrapped), "", ""},
		"pattern without a path":      {anonymousMiddleware()(inner), "x", ""},
	}

	for name, c := range cases {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Pattern = c.pattern

		spans := recordSpans("httpsec.Middleware", func() {
			assert.NotPanics(t, func() { c.handler.ServeHTTP(httptest.NewRecorder(), req) }, name)
		})

		require.Len(t, spans, 1, name)

		got, ok := spans[0].attr("http.route")
		assert.Equal(t, c.want != "", ok, name)
		assert.Equal(t, c.want, got, name)
		assert.NotContains(t, got, "RESET-TOKEN", name)
	}
}
