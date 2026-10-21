// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestLoopbackRedirect pins the comparison of RFC 8252 §7.3: two loopback
// IP redirect URIs match when they are byte-for-byte equal once the port of
// each authority is removed.
func TestLoopbackRedirect(t *testing.T) {
	t.Parallel()

	cases := []struct {
		registered, requested string
		match                 bool
	}{
		{"http://127.0.0.1/cb", "http://127.0.0.1:1/cb", true},
		{"http://127.0.0.1:8080/cb", "http://127.0.0.1:9090/cb", true},
		{"http://127.0.0.1:8080/cb", "http://127.0.0.1/cb", true},
		{"http://[::1]/cb", "http://[::1]:65535/cb", true},
		{"http://127.0.0.1/cb?x=1", "http://127.0.0.1:2/cb?x=1", true},
		{"http://127.0.0.1", "http://127.0.0.1:2", true},
		{"http://127.0.0.1/cb", "http://127.0.0.1:2/cb?", false},
		{"http://127.0.0.1/cb", "http://127.0.0.1:2/cb#", false},
		{"http://127.0.0.1/cb", "http://[::1]:2/cb", false},
		{"http://127.0.0.1/cb", "http://127.0.0.1:0/cb", false},
		{"http://127.0.0.1/cb", "http://127.0.0.1:00001/cb", false},
		{"http://127.0.0.1/cb", "http://127.0.0.1:123456/cb", false},
		{"http://127.0.0.1/cb", "http://127.0.0.1:65536/cb", false},
		{"http://127.0.0.1/cb", "http://127.0.0.1:-1/cb", false},
		{"http://127.0.0.1/cb", "http://127.0.0.1:1:2/cb", false},
		{"http://localhost/cb", "http://localhost:2/cb", false},
		{"https://127.0.0.1/cb", "https://127.0.0.1:2/cb", false},
		{"http://127.0.0.1:0/cb", "http://127.0.0.1:2/cb", false},
		{"http://user@127.0.0.1/cb", "http://user@127.0.0.1:2/cb", false},
	}

	for _, tc := range cases {
		assert.Equal(t, tc.match, loopbackRedirect(tc.registered, tc.requested), "%s vs %s", tc.registered, tc.requested)
	}
}

// loopbackPort matches the ":port" right after a loopback IP literal.
var loopbackPort = regexp.MustCompile(`^http://(127\.0\.0\.1|\[::1\])(:[0-9]*)?`)

// FuzzLoopbackRedirect checks the property behind loopbackRedirect: a match
// means both URIs are http loopback IP redirect URIs with a valid port, and
// identical once that port is removed — the requested one parses with the
// same host, path, query and fragment as the registered one.
func FuzzLoopbackRedirect(f *testing.F) {
	for _, seed := range [][2]string{
		{"http://127.0.0.1/cb", "http://127.0.0.1:51004/cb"},
		{"http://[::1]/cb", "http://[::1]:1@evil.example/cb"},
		{"http://127.0.0.1/cb", "http://127.0.0.1:51004/cb#x"},
		{"http://127.0.0.1/cb?a=%2F", "http://127.0.0.1:2/cb?a=%2F"},
		{"http://127.0.0.1/cb", "http://127.0.0.1:2/cb?"},
	} {
		f.Add(seed[0], seed[1])
	}

	f.Fuzz(func(t *testing.T, registered, requested string) {
		if !loopbackRedirect(registered, requested) {
			return
		}

		strip := func(s string) string { return loopbackPort.ReplaceAllString(s, "http://$1") }
		if strip(registered) != strip(requested) {
			t.Fatalf("%q matches %q but differs beyond the port", requested, registered)
		}

		u, err := url.Parse(requested)
		if err != nil {
			return // not a URI at all: ValidateRedirectURI refuses the registered twin
		}

		if u.Scheme != "http" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "::1") || u.User != nil {
			t.Fatalf("%q matched but is no loopback IP redirect URI", requested)
		}

		if p := u.Port(); p != "" && (strings.HasPrefix(p, "0") || len(p) > 5) {
			t.Fatalf("%q matched with port %q", requested, p)
		}
	})
}

// FuzzAuthorizeRedirectTarget pins RFC 6749 §3.1.2 and §4.1.2 together:
// whatever redirect URI ValidateRedirectURI accepts, the response
// parameters appended to its query come back exactly once, with their
// values — none glued to a registered value, none duplicated.
func FuzzAuthorizeRedirectTarget(f *testing.F) {
	for _, seed := range []string{
		"https://app.example/cb", "https://app.example/cb?", "https://app.example/cb?&", "https://app.example/cb?a=1&",
		"https://app.example/cb?a=1;b=2", "https://app.example/cb?flag", "https://app.example/cb?x=%26code%3D1",
		"https://app.example/cb?next=/home?", "https://app.example/cb?next=https://partner.example/landing?",
		"com.example.app:/cb??", "com.example.app:/cb?y=1", "http://127.0.0.1:5/cb?z", "https://app.example/cb?a=b=c",
	} {
		f.Add(seed)
	}

	want := url.Values{paramCode: {"C"}, paramState: {"S"}, "iss": {"I"}}

	f.Fuzz(func(t *testing.T, uri string) {
		if ValidateRedirectURI(Profile20, uri) != nil {
			return
		}

		target := authorizeRedirectTarget(uri, want, false)
		if !strings.HasPrefix(target, uri) {
			t.Fatalf("%q -> %q: the registered URI is not kept", uri, target)
		}

		u, err := url.Parse(target)
		if err != nil {
			t.Fatalf("%q -> unparsable %q: %v", uri, target, err)
		}

		if u.Fragment != "_" || strings.Count(target, "#") != 1 {
			t.Fatalf("%q -> %q: the fragment is not reset to _ (RFC 9700 §4.1.3)", uri, target)
		}

		// The error reports a registered ";" pair, skipped: not one of ours.
		got, _ := url.ParseQuery(u.RawQuery)
		for name, values := range want {
			if len(got[name]) != 1 || got[name][0] != values[0] {
				t.Fatalf("%q -> %q: %s = %q, want %q once", uri, target, name, got[name], values[0])
			}
		}
	})
}
