// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp

import (
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOriginOf(t *testing.T) {
	t.Parallel()

	for raw, want := range map[string]string{
		"https://IdP.Example.com/metadata":   "https://idp.example.com:443",
		"https://idp.example.com:443/other":  "https://idp.example.com:443",
		"https://idp.example.com:8443/x":     "https://idp.example.com:8443",
		"http://idp.example.com/x":           "http://idp.example.com:80",
		"http://idp.example.com:80/x":        "http://idp.example.com:80",
		"https://[0:0:0:0:0:0:0:1]:8443/x":   "https://[::1]:8443",
		"https://127.0.0.1/x":                "https://127.0.0.1:443",
		"https://[2001:db8::A]/x":            "https://[2001:db8::a]:443",
		"https://idp.example.com.evil.com/x": "https://idp.example.com.evil.com:443",
	} {
		u, err := url.Parse(raw)
		require.NoError(t, err)
		assert.Equal(t, want, originOf(u), raw)
	}
}

func TestOutboundHost(t *testing.T) {
	t.Parallel()

	label := strings.Repeat("a", 63)

	for host, want := range map[string]bool{
		"idp.example.com":                    true,
		"IDP.Example.COM":                    true,
		"xn--bcher-kva.example":              true,
		"a-b.c1":                             true,
		"127.0.0.1":                          true,
		"::1":                                true,
		"idp.0x7f":                           false,
		"idp.0X1f":                           false,
		"idp.0x":                             false,
		"idp.0xg1":                           true,
		"127.1":                              false,
		"2130706433":                         false,
		"":                                   false,
		"idp..example.com":                   false,
		"-idp.example.com":                   false,
		"idp_x.example.com":                  false,
		"fe80::1%en0":                        false,
		strings.Repeat(label+".", 4) + "com": false, // 260 bytes
		label + "a.com":                      false, // 64-byte label
	} {
		assert.Equal(t, want, outboundHost(host), "%q", host)
	}
}
