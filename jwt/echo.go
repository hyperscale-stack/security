// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec

import "unicode/utf8"

// maxEchoedLength bounds every token-supplied value — a kid, an alg, an
// issuer, a parser's message quoting its input — that the package copies
// into an error message or a span attribute (RFC 8725 §3.10: never trust
// received values; a token up to the size bound would otherwise flood logs
// and traces).
const maxEchoedLength = 128

// clip returns s cut to at most maxEchoedLength bytes on a rune boundary,
// followed by "…" when it was cut.
func clip(s string) string {
	if len(s) <= maxEchoedLength {
		return s
	}

	cut := maxEchoedLength
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}

	return s[:cut] + "…"
}

// clippedError bounds the message of an error returned by a third-party
// parser, which may quote the input it refused (go-jose quotes raw header
// values, encoding/json whole number literals): the message is clipped
// once, when the error is wrapped — an error kept and reported again, such
// as a JWK Set's last fetch error, never rebuilds the long one — and
// Unwrap keeps the chain for errors.Is and errors.As.
type clippedError struct {
	msg string
	err error
}

// clipError wraps err in a clippedError.
func clipError(err error) error { return clippedError{msg: clip(err.Error()), err: err} }

// Error implements error with the clipped message of the wrapped error.
func (e clippedError) Error() string { return e.msg }

// Unwrap exposes the wrapped error.
func (e clippedError) Unwrap() error { return e.err }
