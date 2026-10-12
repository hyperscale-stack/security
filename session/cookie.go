// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session

import "net/http"

// CookieReader is implemented by the carriers that expose the request's
// cookies: httpsec.Carrier does, the grpcsec and connectrpcsec carriers do
// not. The [Manager] reads its session cookie through CookiesNamed only —
// never through Get or Values, which read header fields — so a session is
// taken neither from the URL nor from a header named like the cookie. With a
// carrier that does not implement it, the request carries no session.
type CookieReader interface {
	// CookiesNamed returns the request cookies named name, in order
	// (http.Request.CookiesNamed).
	CookiesNamed(name string) []*http.Cookie
}
