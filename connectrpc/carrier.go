// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package connectrpcsec

import (
	"net/http"

	"github.com/hyperscale-stack/security"
)

// Carrier adapts a ConnectRPC request to [security.Carrier].
//
// Reads consult the request header. ConnectRPC speaks net/http, so the keys
// follow http.Header semantics (case-insensitive, canonicalised via
// textproto.CanonicalMIMEHeaderKey); the conventional "Authorization"
// spelling works directly with no manual case folding.
//
// Writes accumulate in a private staged header that the interceptor flushes
// onto the live response header once one is available — immediately for a
// streaming handler (conn.ResponseHeader() is live) and after the handler
// runs for a unary call (the response Header()). This lets an ErrorMapper or
// an extractor attach, e.g., a diagnostic header alongside the response.
//
// Carrier is NOT safe for concurrent use; one instance per RPC.
type Carrier struct {
	in  http.Header
	out http.Header
}

// NewCarrier builds a Carrier from a request header. When h is nil (a unit
// test, a non-Connect caller) the read side is simply empty.
func NewCarrier(h http.Header) *Carrier {
	if h == nil {
		h = http.Header{}
	}

	return &Carrier{in: h, out: http.Header{}}
}

// Get implements [security.Carrier]. Returns the first value for key.
func (c *Carrier) Get(key string) string {
	return c.in.Get(key)
}

// Values implements [security.Carrier].
func (c *Carrier) Values(key string) []string {
	return c.in.Values(key)
}

// Set implements [security.Carrier]. The value is staged in the response
// header; the interceptor flushes it onto the live response.
func (c *Carrier) Set(key, value string) {
	c.out.Set(key, value)
}

// Add implements [security.Carrier].
func (c *Carrier) Add(key, value string) {
	c.out.Add(key, value)
}

// ResponseHeader returns the staged response header. The interceptor calls it
// after the engine / handler run and, when non-empty, copies it onto the live
// response header.
func (c *Carrier) ResponseHeader() http.Header { return c.out }

// Compile-time check.
var _ security.Carrier = (*Carrier)(nil)
