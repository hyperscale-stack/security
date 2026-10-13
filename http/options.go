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
// errors into HTTP responses (and by [Authorize] behind this middleware).
// The default mapper is [DefaultErrorMapper] built from
// [WithChallengeScheme] and [WithRealm].
func WithErrorMapper(m ErrorMapper) Option {
	return func(c *config) { c.errorMapper = m }
}

// WithRealm sets the "realm" parameter of the WWW-Authenticate challenges
// sent by the default [ErrorMapper]. Default: [DefaultRealm]. The realm is a
// protection-space label (RFC 9110 §11.5) sent as a quoted-string: visible
// ASCII, spaces and tabs only — anything else makes [Middleware] panic.
// Consumers MUST NOT rely on its value for authorisation decisions.
func WithRealm(realm string) Option {
	return func(c *config) { c.realm = realm }
}

// WithChallengeScheme sets the authentication scheme advertised by the
// default [ErrorMapper] — the scheme your extractors accept: "Bearer"
// (default) or "Basic". A Basic challenge carries charset="UTF-8"
// (RFC 7617 §2.1); only a Bearer challenge carries RFC 6750 error codes.
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
