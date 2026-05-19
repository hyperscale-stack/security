// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package httpsec

// config is the consolidated configuration of a [Middleware]. It is built up
// by applying [Option] values to a zero value carrying sensible defaults.
type config struct {
	errorMapper       ErrorMapper
	realm             string
	challengeScheme   string
	anonymousFallback bool
}

// Option configures a [Middleware]. Options compose via Middleware([options...]).
type Option func(*config)

// WithErrorMapper overrides the [ErrorMapper] used to translate security
// errors into HTTP responses. The default mapper produces RFC 7235-compliant
// 401/403/400 responses with a configurable challenge scheme.
func WithErrorMapper(m ErrorMapper) Option {
	return func(c *config) { c.errorMapper = m }
}

// WithRealm sets the "realm" parameter of WWW-Authenticate challenges sent by
// the default [ErrorMapper]. RFC 7235 §2.2 allows realm to be any quoted
// string; consumers MUST NOT rely on its value for authorisation decisions.
func WithRealm(realm string) Option {
	return func(c *config) { c.realm = realm }
}

// WithChallengeScheme overrides the authentication scheme advertised by the
// default [ErrorMapper] (e.g. "Bearer", "Basic"). Default: "Bearer".
func WithChallengeScheme(scheme string) Option {
	return func(c *config) { c.challengeScheme = scheme }
}

// WithAnonymousFallback controls what happens when no extractor finds any
// credential. When set to true, the middleware lets the request through with
// the anonymous [security.Authentication]; downstream code (e.g.
// [Authorize]) is responsible for the rejection.
//
// Default: false (strict — return 401 immediately).
func WithAnonymousFallback(allow bool) Option {
	return func(c *config) { c.anonymousFallback = allow }
}
