// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/outbound"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// limitedServer builds the demo with one connection and the given abuse
// bounds; login starts reach it without a browser (no Origin, no
// Sec-Fetch-Site: http.CrossOriginProtection lets them through).
func limitedServer(t *testing.T, maxPending, perMinute int) http.Handler {
	t.Helper()

	acme := newFakeProvider(t, "user-1")
	base := "https://rp.example.com"
	acme.register("rp-acme", "acme-secret", base+"/oidc/acme/callback")

	pool := x509.NewCertPool()
	pool.AddCert(acme.srv.Certificate())

	handler, err := newServer(t.Context(), config{
		BaseURL:              base,
		Connections:          []connectionConfig{{ID: "acme", Issuer: acme.issuer(), ClientID: "rp-acme", ClientSecret: "acme-secret"}},
		Outbound:             outbound.Policy{AllowedPrefixes: outbound.LoopbackPrefixes(), RootCAs: pool},
		TransactionKeys:      [][]byte{[]byte("an example transaction key of 32+ bytes")},
		MaxPendingLogins:     maxPending,
		LoginStartsPerMinute: perMinute,
	})
	require.NoError(t, err)

	return handler
}

// startFrom POSTs a login start from remoteAddr.
func startFrom(handler http.Handler, remoteAddr string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "https://rp.example.com/login/acme", nil)
	req.RemoteAddr = remoteAddr

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	return rec
}

// TestLoginFloodIsBounded checks the demo's per-client limit: an
// unauthenticated client looping on POST /login/{connection} gets its
// budget of starts, then 429 Too Many Requests with Retry-After (RFC 6585
// §4, RFC 9110 §10.2.3), while other clients keep starting logins. An IPv6
// /64 is one client.
func TestLoginFloodIsBounded(t *testing.T) {
	t.Parallel()

	handler := limitedServer(t, 1_000, 5)

	codes := map[int]int{}

	for range 200 {
		rec := startFrom(handler, "203.0.113.7:4321")
		codes[rec.Code]++

		if rec.Code == http.StatusTooManyRequests {
			assert.Equal(t, "60", rec.Header().Get("Retry-After"))
			assert.Empty(t, rec.Header().Values("Set-Cookie"), "a refused start sets no cookie")
		}
	}

	assert.Equal(t, map[int]int{http.StatusSeeOther: 5, http.StatusTooManyRequests: 195}, codes)
	assert.Equal(t, http.StatusSeeOther, startFrom(handler, "198.51.100.9:4321").Code, "another client is not limited")

	for range 5 {
		require.Equal(t, http.StatusSeeOther, startFrom(handler, "[2001:db8:1:2::1]:443").Code)
	}

	assert.Equal(t, http.StatusTooManyRequests, startFrom(handler, "[2001:db8:1:2::ffff]:443").Code, "the same /64")
	assert.Equal(t, http.StatusSeeOther, startFrom(handler, "[2001:db8:1:3::1]:443").Code, "another /64")
}

// TestLoginFloodFromOneNetworkIsBounded checks the demo's per-network
// limit with its defaults: a client holding many addresses of one network —
// 500 /64s of one IPv6 /48 (a tunnel broker hands one out for free), 50
// addresses of one IPv4 /24 — gets a few clients' worth of starts, and
// cannot fill the store against everyone else.
func TestLoginFloodFromOneNetworkIsBounded(t *testing.T) {
	t.Parallel()

	handler := limitedServer(t, 0, 0) // the defaults

	accepted := func(addrs []string, starts int) int {
		n := 0

		for _, addr := range addrs {
			for range starts {
				if startFrom(handler, addr).Code == http.StatusSeeOther {
					n++
				}
			}
		}

		return n
	}

	var six, four []string

	for i := range 500 {
		six = append(six, fmt.Sprintf("[2001:db8:42:%x::1]:443", i))
	}

	for i := range 50 {
		four = append(four, fmt.Sprintf("203.0.113.%d:4321", i+1))
	}

	assert.Equal(t, 60, accepted(six, 20), "one IPv6 /48 gets three clients' worth")
	assert.Equal(t, 60, accepted(four, 20), "one IPv4 /24 too")

	assert.Equal(t, http.StatusSeeOther, startFrom(handler, "198.51.100.77:1234").Code, "another network still signs in")
	assert.Equal(t, http.StatusSeeOther, startFrom(handler, "[2001:db8:43::1]:443").Code)
}

// TestPendingLoginsAreBounded checks the demo's store capacity: once it
// holds MaxPendingLogins pending logins, a start from any client gets 503
// Service Unavailable with Retry-After.
func TestPendingLoginsAreBounded(t *testing.T) {
	t.Parallel()

	handler := limitedServer(t, 5, 100)

	for i := range 5 {
		require.Equal(t, http.StatusSeeOther, startFrom(handler, "203.0.113."+string(rune('1'+i))+":4321").Code)
	}

	rec := startFrom(handler, "198.51.100.9:4321")
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, "60", rec.Header().Get("Retry-After"))
	assert.Empty(t, rec.Header().Values("Set-Cookie"))
}

// TestLoginLimiterBudgets checks the two tiers: each client's budget, and
// its network's — networkShare times as many starts, shared by the clients
// of an IPv4 /24 or an IPv6 /48.
func TestLoginLimiterBudgets(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_800_000_000, 0)
	l := newLoginLimiter(2, 100, time.Minute, func() time.Time { return now })

	for _, network := range [][]string{
		{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"},
		{"2001:db8:1:1::1", "2001:db8:1:2::1", "2001:db8:1:3::1", "2001:db8:1:4::1"},
	} {
		first := netip.MustParseAddr(network[0])

		assert.True(t, l.allow(first))
		assert.True(t, l.allow(first))
		assert.False(t, l.allow(first), "%s: the client's budget is spent", first)

		for _, client := range network[1:3] {
			addr := netip.MustParseAddr(client)
			assert.True(t, l.allow(addr), client)
			assert.True(t, l.allow(addr), client)
		}

		assert.False(t, l.allow(netip.MustParseAddr(network[3])), "%s: the network's budget (3 × 2) is spent", network[3])
	}

	assert.True(t, l.allow(netip.MustParseAddr("198.51.100.1")), "another /24")
	assert.True(t, l.allow(netip.MustParseAddr("2001:db8:2::1")), "another /48")

	now = now.Add(59 * time.Second)
	assert.False(t, l.allow(netip.MustParseAddr("192.0.2.1")), "same window")

	now = now.Add(time.Second)
	assert.True(t, l.allow(netip.MustParseAddr("192.0.2.1")), "a new window")
	assert.True(t, l.allow(netip.MustParseAddr("192.0.2.4")), "the network's budget too")
}

// TestLoginLimiterOverflow checks the bound on each tier's table: the
// prefixes it cannot track share one overflow budget, as do unknown peers,
// while the tracked ones keep theirs.
func TestLoginLimiterOverflow(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_800_000_000, 0)
	l := newLoginLimiter(2, 2, time.Minute, func() time.Time { return now })

	a, b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.1")

	assert.True(t, l.allow(a))
	assert.True(t, l.allow(b), "both tiers now track two prefixes")

	assert.True(t, l.allow(netip.MustParseAddr("203.0.113.1")), "an untracked client uses the overflow budget")
	assert.True(t, l.allow(netip.Addr{}), "so does an unknown peer")
	assert.False(t, l.allow(netip.MustParseAddr("100.64.0.1")), "the client tier's overflow budget is spent")
	assert.True(t, l.allow(a), "a tracked client keeps its own budget")
}

// TestClientAddr checks the address a login start counts against, and the
// prefixes of each tier, IPv4-mapped addresses unmapped.
func TestClientAddr(t *testing.T) {
	t.Parallel()

	tiers := newLoginLimiter(1, 10, time.Minute, time.Now).tiers

	for remote, want := range map[string][2]string{
		"192.0.2.1:1234":          {"192.0.2.1/32", "192.0.2.0/24"},
		"[::ffff:192.0.2.1]:1234": {"192.0.2.1/32", "192.0.2.0/24"},
		"[2001:db8:1:2::1]:443":   {"2001:db8:1:2::/64", "2001:db8:1::/48"},
		"[fe80::1%eth0]:443":      {"fe80::/64", "fe80::/48"},
	} {
		addr := clientAddr(remote)
		assert.Equal(t, mustPrefix(t, want[0]), tiers[0].key(addr, 10), remote)
		assert.Equal(t, mustPrefix(t, want[1]), tiers[1].key(addr, 10), remote)
	}

	assert.False(t, clientAddr("not an address").IsValid())
	assert.Equal(t, overflow, tiers[0].key(clientAddr("not an address"), 10), "an unknown peer counts against the overflow budget")
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()

	p, err := netip.ParsePrefix(s)
	require.NoError(t, err)

	return p
}
