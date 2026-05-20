// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session_test

import (
	"net/http"
	"strings"
)

// mapCarrier is a minimal security.Carrier for the session tests. It models
// a browser cookie jar: cookies set via Add("Set-Cookie", …) on one
// "response" are parsed and replayed as readable cookie values on the next
// "request" via replay().
type mapCarrier struct {
	// cookies are the request-side cookies the Manager reads via Get(name).
	cookies map[string]string
	// setCookies are the Set-Cookie headers the Manager staged via Add.
	setCookies []string
}

func newCarrier() *mapCarrier {
	return &mapCarrier{cookies: map[string]string{}}
}

func (c *mapCarrier) Get(key string) string {
	// The session Manager only ever reads cookies by name.
	return c.cookies[key]
}

func (c *mapCarrier) Values(key string) []string {
	if v, ok := c.cookies[key]; ok {
		return []string{v}
	}

	return nil
}

func (c *mapCarrier) Set(key, value string) {
	if key == "Set-Cookie" {
		c.setCookies = []string{value}

		return
	}
}

func (c *mapCarrier) Add(key, value string) {
	if key == "Set-Cookie" {
		c.setCookies = append(c.setCookies, value)
	}
}

// replay parses the Set-Cookie headers staged on c and returns a fresh
// carrier whose request-side cookies carry them — the next request of the
// same browser. Deleted cookies (Max-Age<0) are dropped.
func (c *mapCarrier) replay() *mapCarrier {
	next := newCarrier()

	resp := http.Response{Header: http.Header{"Set-Cookie": c.setCookies}}
	for _, ck := range resp.Cookies() {
		if ck.MaxAge < 0 {
			continue // logout / expired cookie
		}

		next.cookies[ck.Name] = ck.Value
	}

	return next
}

// lastSetCookie returns the most recent Set-Cookie header value (for
// attribute assertions: Secure, HttpOnly, SameSite, Max-Age).
func (c *mapCarrier) lastSetCookie() string {
	if len(c.setCookies) == 0 {
		return ""
	}

	return c.setCookies[len(c.setCookies)-1]
}

// hasAttr reports whether the last Set-Cookie header carries attr
// (case-insensitive substring match — fine for the fixed attribute names).
func (c *mapCarrier) hasAttr(attr string) bool {
	return strings.Contains(strings.ToLower(c.lastSetCookie()), strings.ToLower(attr))
}

// testKey is a fixed 32-byte codec key used across the suite.
var testKey = []byte("0123456789abcdef0123456789abcdef")
