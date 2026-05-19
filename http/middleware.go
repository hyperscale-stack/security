// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package httpsec

import (
	"context"
	"errors"
	"net/http"

	"github.com/hyperscale-stack/security"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

const tracerName = "github.com/hyperscale-stack/security/http"

// Attribute keys emitted by the HTTP middleware. The "security." prefix
// keeps the namespace aligned with the core; the few HTTP-specific facts
// (method, route) reuse the OpenTelemetry semantic conventions.
const (
	attrHTTPMethod      = attribute.Key("http.method")
	attrHTTPRoute       = attribute.Key("http.route")
	attrSecurityHandled = attribute.Key("security.handled")
)

// Middleware wires a [security.Engine] into the net/http pipeline.
//
// On success the next handler runs with the request context enriched via
// [security.WithAuthentication]. On failure the configured [ErrorMapper]
// writes the response and the next handler is NOT invoked.
//
// When no extractor finds any credential the behavior depends on
// [WithAnonymousFallback]: by default the request is rejected with
// 401 Unauthorized, so applications fail closed.
func Middleware(engine security.Engine, opts ...Option) func(http.Handler) http.Handler {
	cfg := buildConfig(opts...)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, span := otel.Tracer(tracerName).Start(r.Context(), "httpsec.Middleware")
			defer span.End()

			span.SetAttributes(
				attrHTTPMethod.String(r.Method),
				attrHTTPRoute.String(routeFromContext(ctx, r)),
			)

			carrier := NewCarrier(w, r.WithContext(ctx))

			newCtx, auth, err := engine.Process(ctx, carrier)
			if err != nil && !isNoCredential(err, cfg) {
				cfg.errorMapper.Map(w, r, err)

				return
			}

			if !auth.IsAuthenticated() && !cfg.anonymousFallback {
				cfg.errorMapper.Map(w, r, security.ErrInvalidCredentials)

				return
			}

			span.SetAttributes(attrSecurityHandled.Bool(true))

			next.ServeHTTP(w, r.WithContext(newCtx))
		})
	}
}

// buildConfig applies opts to a default config — a Bearer challenge with
// an empty realm and no anonymous fallback (deny-by-default).
func buildConfig(opts ...Option) *config {
	cfg := &config{
		challengeScheme: "Bearer",
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

// routeFromContext returns the http.route attribute. The stdlib mux does not
// publish a route abstraction, so we fall back to the URL path. Adapters for
// chi / gorilla / gin can install a context value under the same private
// type to override this.
func routeFromContext(_ context.Context, r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}

	return r.URL.Path
}
