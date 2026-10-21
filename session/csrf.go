// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
)

// CSRFToken returns a CSRF token of the session to render into a form (a
// hidden field) or a <meta> tag, so the browser can echo it back on
// state-changing requests. The session's secret lives in the encrypted,
// HttpOnly session cookie, which page scripts cannot read; what is rendered
// is masked anew on every call — base64url(mask ‖ mask ⊕ secret) with a
// fresh random mask —, so the same secret never appears twice in responses
// a compression side channel (BREACH) could compare. Any token CSRFToken
// returned for the session verifies with [VerifyCSRF]. Render this value,
// never Session.CSRFToken. A script injected into the page (XSS) can still
// read it: no CSRF defense survives XSS. It returns "" for a nil session or
// a session without secret.
func CSRFToken(s *Session) string {
	if s == nil || s.CSRFToken == "" {
		return ""
	}

	secret := []byte(s.CSRFToken)

	out := make([]byte, 2*len(secret))
	mask, masked := out[:len(secret)], out[len(secret):]

	_, _ = rand.Read(mask) // never fails (crypto/rand, Go 1.24+)

	subtle.XORBytes(masked, mask, secret)

	return base64.RawURLEncoding.EncodeToString(out)
}

// VerifyCSRF reports whether presented is a CSRF token of the session — one
// [CSRFToken] rendered for it: presented is unmasked and compared with the
// session's secret in constant time, so the response time leaks nothing of
// it. An empty or malformed token never verifies, and neither does the raw
// secret (Session.CSRFToken).
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
	if s == nil || s.CSRFToken == "" {
		return false
	}

	// An empty token decodes to nothing: the length check refuses it.
	raw, err := base64.RawURLEncoding.DecodeString(presented)
	if err != nil || len(raw) != 2*len(s.CSRFToken) {
		return false
	}

	half := len(raw) / 2
	unmasked := make([]byte, half)
	subtle.XORBytes(unmasked, raw[:half], raw[half:])

	return subtle.ConstantTimeCompare(unmasked, []byte(s.CSRFToken)) == 1
}
