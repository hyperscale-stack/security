// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session

import "crypto/subtle"

// CSRFToken returns the per-session CSRF token. The application embeds it
// into rendered forms (a hidden field) or a <meta> tag so the browser can
// echo it back on state-changing requests. The token lives inside the
// encrypted, HttpOnly session cookie, so it is never directly readable by
// page JavaScript — only the server, which decrypts the cookie, knows it.
func CSRFToken(s *Session) string {
	if s == nil {
		return ""
	}

	return s.CSRFToken
}

// VerifyCSRF reports whether presented matches the session's CSRF token.
// The comparison is constant-time to avoid leaking the token through
// response-timing analysis.
//
// This is the synchronizer-token pattern: the server holds the canonical
// token in the (encrypted) session and checks the value the client echoed
// back in, e.g., the "X-CSRF-Token" header or a form field. Unlike the
// plain double-submit-cookie pattern it does not rely on a second,
// JavaScript-readable cookie, so it is robust even against subdomain
// cookie-injection.
func VerifyCSRF(s *Session, presented string) bool {
	if s == nil || s.CSRFToken == "" || presented == "" {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(s.CSRFToken), []byte(presented)) == 1
}
