// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package connectrpcsec

import (
	"context"
	"net/http"
	"strings"
)

// The twin of the formatting helpers below lives in http/challenge.go: the
// dependency policy keeps this module off httpsec, and both are pinned by
// the same table tests.

// isToken reports whether s is an RFC 9110 §5.6.2 token — the syntax of an
// auth-scheme.
func isToken(s string) bool {
	if s == "" {
		return false
	}

	for i := range len(s) {
		c := s[i]

		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}

	return true
}

// quoteString renders s as an RFC 9110 §5.6.4 quoted-string: DQUOTE and
// backslash become a quoted-pair, HTAB, SP and visible ASCII stay as they
// are, and anything else — control characters (CR, LF, NUL included,
// RFC 9110 §5.5), DEL, non-ASCII — makes ok false.
func quoteString(s string) (string, bool) {
	var b strings.Builder

	b.Grow(len(s) + 2)
	b.WriteByte('"')

	for i := range len(s) {
		c := s[i]

		switch {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c == '\t' || (c >= 0x20 && c <= 0x7e):
			b.WriteByte(c)
		default:
			return "", false
		}
	}

	b.WriteByte('"')

	return b.String(), true
}

// bearerTokenKey is the context key under which the interceptors tell the
// default mapper whether the request carried a bearer token.
type bearerTokenKey struct{}

// withBearerToken records in ctx whether header carries an Authorization
// field with the Bearer scheme (case-insensitive, RFC 9110 §11.1): the
// RFC 6750 error codes describe why a request made with an access token was
// refused, so they are not sent otherwise.
func withBearerToken(ctx context.Context, header http.Header) context.Context {
	sent := false

	for _, v := range header.Values("Authorization") {
		if scheme, _, _ := strings.Cut(v, " "); strings.EqualFold(scheme, "Bearer") {
			sent = true

			break
		}
	}

	return context.WithValue(ctx, bearerTokenKey{}, sent)
}

func bearerTokenSent(ctx context.Context) bool {
	sent, _ := ctx.Value(bearerTokenKey{}).(bool)

	return sent
}
