// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import "net/http"

// setAuthorizeHeaders sets the headers every /authorize response carries,
// before the handler does anything else — the ConsentFunc's login and
// consent pages, the redirects and the bare errors alike:
//
//   - X-Frame-Options: DENY and Content-Security-Policy: frame-ancestors
//     'none' — the authorization server MUST prevent clickjacking (RFC 6749
//     §10.13, RFC 9700 §4.16). The CSP is added, not set: a policy an
//     outer handler set is kept, and browsers enforce both.
//   - Cache-Control: no-store — the pages and redirects carry codes,
//     states and tokens.
//   - Referrer-Policy: same-origin — no Referer leaks the request URL to
//     another origin, the client's included (RFC 9700 §4.2.4). Not
//     no-referrer: under it browsers send Origin: null on the consent page's
//     own POST, which the Origin check of CSRF defenses then refuses.
//
// A redirect carrying them still lands in a frame — browsers check framing
// on the final response — so prompt=none in an iframe keeps working.
func setAuthorizeHeaders(h http.Header) {
	h.Set("X-Frame-Options", "DENY")
	h.Add("Content-Security-Policy", "frame-ancestors 'none'")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "same-origin")
}

// redirectStatus is the status of a redirect answering r: 303 See Other
// for a POST — which may carry the resource owner's credentials, and which
// only 303 unambiguously turns into a GET (RFC 9700 §4.12; never 307) —
// and 302 Found otherwise (RFC 6749 §4.1.2).
func redirectStatus(r *http.Request) int {
	if r.Method == http.MethodPost {
		return http.StatusSeeOther
	}

	return http.StatusFound
}
