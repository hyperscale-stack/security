// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	"crypto/x509"
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

// TestLoginLimiter checks the fixed-window limiter: each client's budget,
// the reset at the next window, and the overflow budget the clients share
// once the table is full.
func TestLoginLimiter(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_800_000_000, 0)
	l := newLoginLimiter(2, 2, time.Minute, func() time.Time { return now })

	a, b, c, d := mustPrefix(t, "192.0.2.1/32"), mustPrefix(t, "192.0.2.2/32"), mustPrefix(t, "192.0.2.3/32"), mustPrefix(t, "192.0.2.4/32")

	assert.True(t, l.allow(a))
	assert.True(t, l.allow(a))
	assert.False(t, l.allow(a), "a's budget is spent")
	assert.True(t, l.allow(b))

	assert.True(t, l.allow(c), "the table is full: c uses the overflow budget")
	assert.True(t, l.allow(d), "d shares it")
	assert.False(t, l.allow(c), "the overflow budget is spent")
	assert.True(t, l.allow(b), "a tracked client keeps its own budget")

	now = now.Add(59 * time.Second)
	assert.False(t, l.allow(a), "same window")

	now = now.Add(time.Second)
	assert.True(t, l.allow(a), "a new window")
	assert.True(t, l.allow(c), "c is tracked again")
}

// TestClientPrefix checks what a login start counts against.
func TestClientPrefix(t *testing.T) {
	t.Parallel()

	for remote, want := range map[string]string{
		"192.0.2.1:1234":          "192.0.2.1/32",
		"[::ffff:192.0.2.1]:1234": "192.0.2.1/32",
		"[2001:db8:1:2::1]:443":   "2001:db8:1:2::/64",
		"[fe80::1%eth0]:443":      "fe80::/64",
	} {
		assert.Equal(t, mustPrefix(t, want), clientPrefix(remote), remote)
	}

	assert.Equal(t, overflow, clientPrefix("not an address"), "an unknown peer counts against the overflow budget")
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()

	p, err := netip.ParsePrefix(s)
	require.NoError(t, err)

	return p
}
