// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grpcsec

import "context"

// config is the consolidated interceptor configuration, built from the
// applied [Option] values.
type config struct {
	// errorMapper is the mapper given with WithErrorMapper, nil otherwise.
	errorMapper       ErrorMapper
	anonymousFallback bool
	// panicHandler is the handler given with WithPanicHandler, nil
	// otherwise.
	panicHandler func(ctx context.Context, recovered any)
}

// Option configures an interceptor.
type Option func(*config)

// WithErrorMapper overrides the [ErrorMapper] used to translate security
// errors into gRPC status errors. Without it the authentication
// interceptors use [DefaultErrorMapper], and the authorization interceptors
// use the mapper of the authentication interceptor that ran before them.
func WithErrorMapper(m ErrorMapper) Option {
	return func(c *config) {
		if !isNil(m) {
			c.errorMapper = m
		}
	}
}

// WithAnonymousFallback controls what happens when no extractor finds a
// credential. With true, the RPC proceeds carrying the anonymous
// [security.Authentication] and downstream authorisation interceptors are
// responsible for rejecting it. Default: false (reject with
// codes.Unauthenticated immediately). Invalid credentials are refused
// whatever the fallback.
func WithAnonymousFallback(allow bool) Option {
	return func(c *config) { c.anonymousFallback = allow }
}

// WithPanicHandler sets a handler called with the value of every panic of
// the security pipeline — an extractor, an authenticator, a user loader, a
// decision manager or a voter — that the interceptors recover: they answer
// the RPC as an internal error (codes.Internal with the default mapper) and
// record a "panic recovered" span event, never the value. An outer recovery
// interceptor no longer sees these panics: the handler is where to log them
// or report them, with a stack (runtime/debug.Stack). The value may hold a
// credential — what the panicking code had at hand —: the handler handles
// it under the application's responsibility. It runs in the interceptor,
// before the answer; a panic of the handler itself is ignored. Default:
// none. WithPanicHandler(nil) keeps none.
func WithPanicHandler(handler func(ctx context.Context, recovered any)) Option {
	return func(c *config) { c.panicHandler = handler }
}

// buildConfig applies opts onto the default config.
func buildConfig(opts ...Option) *config {
	cfg := &config{}
	for _, o := range opts {
		o(cfg)
	}

	return cfg
}

// ownMapper returns the configured mapper, or the default one.
func (c *config) ownMapper() ErrorMapper {
	if c.errorMapper != nil {
		return c.errorMapper
	}

	return DefaultErrorMapper()
}

// mapper returns the configured mapper, else the one the authentication
// interceptor published in ctx, else the default one.
func (c *config) mapper(ctx context.Context) ErrorMapper {
	if c.errorMapper != nil {
		return c.errorMapper
	}

	if m, ok := ctx.Value(errorMapperKey{}).(ErrorMapper); ok && m != nil {
		return m
	}

	return DefaultErrorMapper()
}

// errorMapperKey is the context key under which the authentication
// interceptors publish their error mapper for the authorization ones.
type errorMapperKey struct{}

func withErrorMapper(ctx context.Context, m ErrorMapper) context.Context {
	return context.WithValue(ctx, errorMapperKey{}, m)
}
