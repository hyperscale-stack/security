// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient

import (
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/hyperscale-stack/security/outbound"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()

	u, err := url.Parse(raw)
	require.NoError(t, err)

	return u
}

// TestOriginOf checks the RFC 6454 §4 origin the redirect pin compares:
// scheme, host and port, with the scheme's default port, ASCII-only case
// folding and canonical IP literals.
func TestOriginOf(t *testing.T) {
	t.Parallel()

	same := map[string][2]string{
		"default https port":      {"https://op.example/a", "https://op.example:443/b"},
		"default http port":       {"http://op.example/a", "http://op.example:80/"},
		"case of scheme and host": {"HTTPS://OP.Example/a", "https://op.example/b"},
		"IPv6 literal forms":      {"https://[::1]:8443/a", "https://[0:0:0:0:0:0:0:1]:8443/b"},
		"IPv4 default port":       {"https://127.0.0.1/a", "https://127.0.0.1:443/b"},
		"port with a leading 0":   {"https://op.example:8443/a", "https://op.example:08443/b"},
		"case of A and Z":         {"https://AZ.example/a", "https://az.example/b"},
	}

	for name, pair := range same {
		assert.Equal(t, originOf(mustURL(t, pair[0])), originOf(mustURL(t, pair[1])), name)
	}

	different := map[string][2]string{
		"scheme":                   {"https://op.example/a", "http://op.example/a"},
		"scheme on the same port":  {"https://op.example:8443/a", "http://op.example:8443/a"},
		"port":                     {"https://op.example/a", "https://op.example:8443/a"},
		"host":                     {"https://op.example/a", "https://evil.example/a"},
		"suffix":                   {"https://op.example/a", "https://op.example.evil/a"},
		"non-ASCII case variant":   {"https://keycloak.example/a", "https://Keycloak.example/a"}, // KELVIN SIGN folds to k in Unicode only
		"IPv4-mapped IPv6 literal": {"https://127.0.0.1/a", "https://[::ffff:127.0.0.1]/a"},
	}

	for name, pair := range different {
		assert.NotEqual(t, originOf(mustURL(t, pair[0])), originOf(mustURL(t, pair[1])), name)
	}
}

// TestSameOriginRedirect checks the CheckRedirect hook: the outbound
// policy decides first, then every hop must stay on the origin of the
// first request of the exchange.
func TestSameOriginRedirect(t *testing.T) {
	t.Parallel()

	allow := func(*http.Request, []*http.Request) error { return nil }
	request := func(raw string) *http.Request { return &http.Request{URL: mustURL(t, raw)} }
	first := request("https://op.example/.well-known/openid-configuration")

	check := sameOriginRedirect(allow)

	require.NoError(t, check(request("https://OP.example:443/v2"), []*http.Request{first}))
	require.ErrorIs(t, check(request("https://evil.example/"), []*http.Request{first}), outbound.ErrRedirectNotAllowed)
	require.ErrorIs(t, check(request("https://evil.example/"), []*http.Request{first, request("https://op.example/v2")}),
		outbound.ErrRedirectNotAllowed, "a later hop is compared with the first request")

	policy := errors.New("hop limit")
	refuse := sameOriginRedirect(func(*http.Request, []*http.Request) error { return policy })
	require.ErrorIs(t, refuse(request("https://op.example/v2"), []*http.Request{first}), policy,
		"the outbound policy decides first, even on the same origin")
}
