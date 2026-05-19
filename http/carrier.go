// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package httpsec

import (
	"net/http"

	"github.com/hyperscale-stack/security"
)

// Carrier adapts an *http.Request / http.ResponseWriter pair to
// [security.Carrier]. Reads consult headers first, then cookies, then query
// parameters, so header-borne credentials take precedence over URL-borne ones
// (an important defense against credentials leaking through access logs).
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
//   - a nil request makes every Get/Values/Cookie return "" / nil;
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

// Get implements [security.Carrier]. Lookup order: header > cookie > query.
func (c *Carrier) Get(key string) string {
	if c.req == nil {
		return ""
	}

	if v := c.req.Header.Get(key); v != "" {
		return v
	}

	if ck, err := c.req.Cookie(key); err == nil {
		return ck.Value
	}

	return c.req.URL.Query().Get(key)
}

// Values implements [security.Carrier]. Header multi-values take precedence;
// when none are present, cookies (single value) then query parameters
// (multi-value) are consulted in that order.
func (c *Carrier) Values(key string) []string {
	if c.req == nil {
		return nil
	}

	if vs := c.req.Header.Values(key); len(vs) > 0 {
		return vs
	}

	if ck, err := c.req.Cookie(key); err == nil {
		return []string{ck.Value}
	}

	if vs := c.req.URL.Query()[key]; len(vs) > 0 {
		return vs
	}

	return nil
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
