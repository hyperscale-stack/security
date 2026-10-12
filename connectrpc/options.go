// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package connectrpcsec

import "context"

// config is the consolidated interceptor configuration, built from the
// applied [Option] values.
type config struct {
	// errorMapper is the mapper given with WithErrorMapper, or the default
	// one built from the challenge options; nil without either.
	errorMapper       ErrorMapper
	challengeScheme   string
	realm             string
	challengeSet      bool
	anonymousFallback bool
}

// Option configures an interceptor.
type Option func(*config)

// WithErrorMapper overrides the [ErrorMapper] used to translate security
// errors into Connect errors (it takes precedence over [WithChallengeScheme]
// and [WithRealm]). Without it the authentication interceptor uses
// [DefaultErrorMapper], and the authorization interceptor the mapper of the
// authentication interceptor that ran before it.
func WithErrorMapper(m ErrorMapper) Option {
	return func(c *config) {
		if m != nil {
			c.errorMapper = m
		}
	}
}

// WithChallengeScheme sets the scheme of the WWW-Authenticate challenge the
// default mapper sends on Unauthenticated and PermissionDenied errors —
// "Bearer" (default) or "Basic".
func WithChallengeScheme(scheme string) Option {
	return func(c *config) {
		c.challengeScheme = scheme
		c.challengeSet = true
	}
}

// WithRealm sets the realm of the default mapper's challenges. Default:
// [DefaultRealm]. Visible ASCII, spaces and tabs only — anything else makes
// the interceptor constructor panic.
func WithRealm(realm string) Option {
	return func(c *config) {
		c.realm = realm
		c.challengeSet = true
	}
}

// WithAnonymousFallback controls what happens when no extractor finds a
// credential. With true, the RPC proceeds carrying the anonymous
// [security.Authentication] and downstream authorisation interceptors are
// responsible for rejecting it. Default: false (reject with
// connect.CodeUnauthenticated immediately). Invalid credentials are refused
// whatever the fallback.
func WithAnonymousFallback(allow bool) Option {
	return func(c *config) { c.anonymousFallback = allow }
}

// buildConfig applies opts onto the default config. A challenge option
// without an explicit mapper builds the default mapper here, so an invalid
// configuration fails at construction.
func buildConfig(opts ...Option) *config {
	cfg := &config{}
	for _, o := range opts {
		o(cfg)
	}

	if cfg.errorMapper == nil && cfg.challengeSet {
		cfg.errorMapper = DefaultErrorMapper(cfg.challengeScheme, cfg.realm)
	}

	return cfg
}

// ownMapper returns the configured mapper, or the default one.
func (c *config) ownMapper() ErrorMapper {
	if c.errorMapper != nil {
		return c.errorMapper
	}

	return DefaultErrorMapper("", "")
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

	return DefaultErrorMapper("", "")
}

// errorMapperKey is the context key under which the authentication
// interceptor publishes its error mapper for the authorization one.
type errorMapperKey struct{}

func withErrorMapper(ctx context.Context, m ErrorMapper) context.Context {
	return context.WithValue(ctx, errorMapperKey{}, m)
}
