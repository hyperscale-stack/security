// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package httpsec

import (
	"strings"
)

// The twin of this file lives in connectrpc/challenge.go: the dependency
// policy keeps connectrpcsec off this module, and both are pinned by the
// same table tests.

// isToken reports whether s is an RFC 9110 §5.6.2 token — the syntax of an
// auth-scheme.
func isToken(s string) bool {
	for i := range len(s) {
		c := s[i]

		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}

	return s != "" // token = 1*tchar
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

// bearerTokenSent reports whether the request carried an Authorization
// field with the Bearer scheme (auth-scheme names are case-insensitive,
// RFC 9110 §11.1): the RFC 6750 error codes describe why a request made
// with an access token was refused, so they are not sent otherwise.
func bearerTokenSent(values []string) bool {
	for _, v := range values {
		if scheme, _, _ := strings.Cut(v, " "); strings.EqualFold(scheme, "Bearer") {
			return true
		}
	}

	return false
}
