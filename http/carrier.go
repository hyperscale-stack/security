// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package httpsec

import (
	"net/http"

	"github.com/hyperscale-stack/security"
)

// Carrier adapts an *http.Request / http.ResponseWriter pair to
// [security.Carrier].
//
// Get and Values read the request's header fields only — never the URL query
// string, never a cookie named like the key. A credential is therefore
// accepted only from the field its scheme defines (Authorization, RFC 6750
// §2.1, RFC 7617): credentials in URLs leak through access logs, Referer and
// history (RFC 6750 §5.3), a link carrying a session would log the victim
// into the attacker's account, and a cookie named like a header would
// become an ambient credential. CookiesNamed reads the request's cookies
// explicitly; the session module reads its cookie through it.
//
// Writes go to the response writer's header — useful for issuing
// WWW-Authenticate challenges or refreshing a session cookie.
//
// Carrier is NOT safe for concurrent use; one instance per request.
type Carrier struct {
	req *http.Request
	rw  http.ResponseWriter
}

// NewCarrier wraps the request/response pair. Either argument MAY be nil:
//   - a nil request makes every Get/Values/CookiesNamed return "" / nil;
//   - a nil response writer makes every Set/Add a no-op (useful in tests).
func NewCarrier(rw http.ResponseWriter, req *http.Request) *Carrier {
	return &Carrier{req: req, rw: rw}
}

// Request returns the wrapped *http.Request. Middlewares wishing to
// propagate context updates SHOULD prefer Carrier.WithContext().
func (c *Carrier) Request() *http.Request { return c.req }

// WithContext returns a new Carrier whose underlying request carries ctx.
// The ResponseWriter is shared (write-side state lives in the writer).
func (c *Carrier) WithContext(req *http.Request) *Carrier {
	return &Carrier{req: req, rw: c.rw}
}

// Get implements [security.Carrier]. It returns the first value of the
// request header field key, or "" — it never reads the query string or the
// cookies.
func (c *Carrier) Get(key string) string {
	if c.req == nil {
		return ""
	}

	return c.req.Header.Get(key)
}

// Values implements [security.Carrier]. It returns every value of the
// request header field key, or nil — it never reads the query string or the
// cookies.
func (c *Carrier) Values(key string) []string {
	if c.req == nil {
		return nil
	}

	return c.req.Header.Values(key)
}

// CookiesNamed returns the request cookies named name, in the order of the
// Cookie header field lines (RFC 6265 §5.4), or none. It is the explicit
// cookie accessor the session module reads its cookie through
// (session.CookieReader).
func (c *Carrier) CookiesNamed(name string) []*http.Cookie {
	if c.req == nil {
		return nil
	}

	return c.req.CookiesNamed(name)
}

// Set implements [security.Carrier]. It writes to the ResponseWriter's
// header, which controls outbound HTTP responses (e.g. WWW-Authenticate).
func (c *Carrier) Set(key, value string) {
	if c.rw == nil {
		return
	}

	c.rw.Header().Set(key, value)
}

// Add implements [security.Carrier]. Appends to the response header.
func (c *Carrier) Add(key, value string) {
	if c.rw == nil {
		return
	}

	c.rw.Header().Add(key, value)
}

// Compile-time check that Carrier implements security.Carrier.
var _ security.Carrier = (*Carrier)(nil)
