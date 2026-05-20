// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grpcsec

// config is the consolidated interceptor configuration, built from the
// applied [Option] values.
type config struct {
	errorMapper       ErrorMapper
	anonymousFallback bool
}

// Option configures an interceptor.
type Option func(*config)

// WithErrorMapper overrides the [ErrorMapper] used to translate security
// errors into gRPC status errors. Defaults to [DefaultErrorMapper].
func WithErrorMapper(m ErrorMapper) Option {
	return func(c *config) {
		if m != nil {
			c.errorMapper = m
		}
	}
}

// WithAnonymousFallback controls what happens when no extractor finds a
// credential. With true, the RPC proceeds carrying the anonymous
// [security.Authentication] and downstream authorisation interceptors are
// responsible for rejecting it. Default: false (reject with
// codes.Unauthenticated immediately).
func WithAnonymousFallback(allow bool) Option {
	return func(c *config) { c.anonymousFallback = allow }
}

// buildConfig applies opts onto the default config.
func buildConfig(opts ...Option) *config {
	cfg := &config{errorMapper: DefaultErrorMapper()}
	for _, o := range opts {
		o(cfg)
	}

	return cfg
}
