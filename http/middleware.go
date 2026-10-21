// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package httpsec

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/hyperscale-stack/security"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

const tracerName = "github.com/hyperscale-stack/security/http"

// Attribute keys emitted by the HTTP middleware. The "security." prefix
// keeps the namespace aligned with the core; the HTTP facts reuse the
// OpenTelemetry semantic conventions.
const (
	attrHTTPRequestMethod = attribute.Key("http.request.method")
	attrHTTPRoute         = attribute.Key("http.route")
	attrSecurityHandled   = attribute.Key("security.handled")
)

// errEngineContract reports a custom [security.Engine] that returned no
// context or no authentication (nil or a typed nil) without an error: an
// internal error.
var errEngineContract = errors.New("httpsec: the engine returned no context or authentication")

// Middleware wires a [security.Engine] into the net/http pipeline.
//
// On success the next handler runs with the request context enriched via
// [security.WithAuthentication]. On failure the configured [ErrorMapper]
// writes the response and the next handler is NOT invoked.
//
// When no extractor finds any credential the behavior depends on
// [WithAnonymousFallback]: by default the request is rejected with
// 401 Unauthorized ([security.ErrAuthenticationRequired]), so applications
// fail closed. Invalid credentials are refused whatever the fallback.
//
// The middleware stores the request's peer address (r.RemoteAddr) in the
// context as the client address an [security.AttemptLimiter] keys on,
// unless a middleware before it stored one with [security.WithClientAddr]
// — do so behind a reverse proxy, or every request counts as the proxy's.
//
// The middleware makes its error mapper available to [Authorize], so the
// authorization step answers with the same challenge. Middleware panics at
// construction on a nil engine and on an invalid challenge configuration
// (see [DefaultErrorMapper]).
func Middleware(engine security.Engine, opts ...Option) func(http.Handler) http.Handler {
	if engine == nil {
		panic("httpsec: Middleware: nil Engine")
	}

	cfg := buildConfig(opts...)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, span := otel.Tracer(tracerName).Start(r.Context(), "httpsec.Middleware")
			defer span.End()

			span.SetAttributes(attrHTTPRequestMethod.String(requestMethod(r.Method)))

			if route := httpRoute(r.Pattern); route != "" {
				span.SetAttributes(attrHTTPRoute.String(route))
			}

			ctx = withClientAddr(withErrorMapper(ctx, cfg.errorMapper), r.RemoteAddr)

			newCtx, auth, err := engine.Process(ctx, NewCarrier(w, r.WithContext(ctx)))

			switch {
			case err != nil && !isNoCredential(err, cfg):
				cfg.errorMapper.Map(w, r, err)

				return
			case newCtx == nil || isNil(auth):
				cfg.errorMapper.Map(w, r, errEngineContract)

				return
			case !auth.IsAuthenticated() && !cfg.anonymousFallback:
				cfg.errorMapper.Map(w, r, security.ErrAuthenticationRequired)

				return
			}

			span.SetAttributes(attrSecurityHandled.Bool(true))

			next.ServeHTTP(w, r.WithContext(withErrorMapper(newCtx, cfg.errorMapper)))
		})
	}
}

// withClientAddr stores the peer address remoteAddr in ctx as the client
// address, unless ctx carries one already or remoteAddr is not an IP
// address.
func withClientAddr(ctx context.Context, remoteAddr string) context.Context {
	if _, ok := security.ClientAddrFromContext(ctx); ok {
		return ctx
	}

	addr := security.ParseClientAddr(remoteAddr)
	if !addr.IsValid() {
		return ctx
	}

	return security.WithClientAddr(ctx, addr)
}

// buildConfig applies opts to a default config — a Bearer challenge with
// the default realm and no anonymous fallback (deny-by-default).
func buildConfig(opts ...Option) *config {
	cfg := &config{
		challengeScheme: defaultChallengeScheme,
	}

	for _, o := range opts {
		o(cfg)
	}

	if cfg.errorMapper == nil {
		cfg.errorMapper = DefaultErrorMapper(cfg.challengeScheme, cfg.realm)
	}

	return cfg
}

// isNoCredential reports whether err means "no credential found" — the
// engine returns ErrNoExtractor for that. We treat it the same way as a
// successful anonymous extraction so callers needing to fail open can set
// WithAnonymousFallback without also having to filter on this error.
func isNoCredential(err error, cfg *config) bool {
	if !errors.Is(err, security.ErrNoExtractor) {
		return false
	}

	return cfg.anonymousFallback
}

// requestMethod returns the method for the http.request.method attribute:
// one of the RFC 9110 §9 methods or PATCH (RFC 5789), matched exactly —
// methods are case-sensitive — else "_OTHER", so a client cannot write
// arbitrary, unbounded tokens into the span (OpenTelemetry semantic
// conventions).
func requestMethod(method string) string {
	switch method {
	case http.MethodConnect, http.MethodDelete, http.MethodGet, http.MethodHead, http.MethodOptions,
		http.MethodPatch, http.MethodPost, http.MethodPut, http.MethodTrace:
		return method
	default:
		return "_OTHER"
	}
}

// httpRoute returns the path template of a ServeMux pattern
// ("GET example.com/items/{id}" → "/items/{id}"), or "" when the request
// was not routed by a pattern (the middleware wraps the mux): the
// http.route attribute is a low-cardinality template or nothing, never the
// raw path (OpenTelemetry semantic conventions).
func httpRoute(pattern string) string {
	if i := strings.IndexByte(pattern, '/'); i >= 0 {
		return pattern[i:]
	}

	return ""
}

// errorMapperKey is the context key under which the middleware publishes its
// error mapper for Authorize.
type errorMapperKey struct{}

func withErrorMapper(ctx context.Context, m ErrorMapper) context.Context {
	return context.WithValue(ctx, errorMapperKey{}, m)
}

func errorMapperFrom(ctx context.Context) (ErrorMapper, bool) {
	m, ok := ctx.Value(errorMapperKey{}).(ErrorMapper)

	return m, ok && m != nil
}
