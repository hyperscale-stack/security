// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session

import "crypto/subtle"

// CSRFToken returns the per-session CSRF token. The application embeds it
// into rendered forms (a hidden field) or a <meta> tag so the browser can
// echo it back on state-changing requests. Its canonical copy lives in the
// encrypted, HttpOnly session cookie, which page scripts cannot read — but
// the token itself is rendered into the page, where a script injected into
// it (XSS) can read it: no CSRF defense survives XSS.
func CSRFToken(s *Session) string {
	if s == nil {
		return ""
	}

	return s.CSRFToken
}

// VerifyCSRF reports whether presented matches the session's CSRF token.
// The comparison is constant-time to avoid leaking the token through
// response-timing analysis. An empty token never verifies.
//
// VerifyCSRF is a check, not a policy: nothing enforces it for you. Call it
// on every state-changing request (POST, PUT, PATCH, DELETE) that a cookie
// session authenticates, never change state on GET, and add a cross-origin
// check in front of the handlers (net/http's CrossOriginProtection, which
// refuses cross-origin unsafe requests from their Sec-Fetch-Site and Origin
// headers). SameSite=Lax keeps the cookie off cross-site POSTs in current
// browsers but not off same-site requests from a sibling subdomain.
//
// The sign-in form needs a token too, against login CSRF, before there is a
// signed-in session: open a session for the form on a dedicated Manager —
// its own cookie name and purpose, a short TTL — that no [Extractor] reads,
// with Login(ctx, c, nil) when the form is rendered, and check the posted
// token against it:
//
//	form := session.NewManager(codec,
//		session.WithCookieName("__Host-signin"),
//		session.WithPurpose("sign-in form"),
//		session.WithTTL(15*time.Minute))
//
// Never open it on the Manager an Extractor reads: the Engine would extract
// the subject-less session on every request and the [PrincipalLoader]
// refuse it — every page, the sign-in form included, would answer 401.
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
