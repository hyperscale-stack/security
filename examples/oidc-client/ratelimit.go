// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	"net/netip"
	"sync"
	"time"
)

// overflow is the budget shared by the clients the limiter's table cannot
// track, and by requests whose peer address is unknown.
var overflow = netip.Prefix{}

// loginLimiter lets each client start a bounded number of logins per
// window: login starts are unauthenticated, and each stores a pending
// login for the transaction TTL. It counts in fixed windows (simple; at
// most twice the budget across a window boundary) and tracks at most
// maxClients clients per window: beyond them, the other clients share one
// overflow budget, so that a flood from many addresses slows new clients
// down instead of locking them out; the store's capacity bounds the
// memory whatever happens.
//
// Behind a reverse proxy every request comes from the proxy's address:
// key the limit on the client address your proxy forwards — only you know
// which proxy to trust — or rate-limit at the edge.
type loginLimiter struct {
	perWindow  int
	maxClients int
	window     time.Duration
	now        func() time.Time

	mu     sync.Mutex
	start  time.Time
	counts map[netip.Prefix]int
}

func newLoginLimiter(perWindow, maxClients int, window time.Duration, now func() time.Time) *loginLimiter {
	return &loginLimiter{
		perWindow: perWindow, maxClients: maxClients, window: window, now: now,
		counts: make(map[netip.Prefix]int),
	}
}

// allow reports whether client may start a login now, and counts it.
func (l *loginLimiter) allow(client netip.Prefix) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if now := l.now(); now.Sub(l.start) >= l.window {
		l.start = now
		clear(l.counts)
	}

	if _, known := l.counts[client]; !known && len(l.counts) >= l.maxClients {
		client = overflow
	}

	if l.counts[client] >= l.perWindow {
		return false
	}

	l.counts[client]++

	return true
}

// clientPrefix is the client a login start counts against: the peer's
// IPv4 address, or its IPv6 /64 — one subscriber's allocation, which a
// single client can rotate through.
func clientPrefix(remoteAddr string) netip.Prefix {
	peer, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return overflow
	}

	addr := peer.Addr().Unmap()

	bits := 32
	if addr.Is6() {
		bits = 64
	}

	prefix, _ := addr.Prefix(bits) // fails only for a length beyond the address's

	return prefix
}
