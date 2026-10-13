// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	"net/netip"
	"sync"
	"time"
)

// networkShare is how many clients' worth of login starts one network — an
// IPv4 /24, an IPv6 /48 — may make per window.
const networkShare = 3

// overflow is the prefix, in each tier, of the requests whose peer address
// is unknown and, once the tier tracks as many prefixes as it may, of the
// prefixes it does not track: they share one budget.
var overflow = netip.Prefix{}

// tier counts the login starts of one window per prefix of one length.
type tier struct {
	bits4, bits6 int // the prefix length of IPv4 and IPv6 addresses
	budget       int // the starts a prefix may make per window
	counts       map[netip.Prefix]int
}

// key is the prefix addr counts against: its own, or overflow once the
// tier tracks maxPrefixes prefixes. The zero Addr of an unknown peer has
// the zero Prefix, overflow.
func (t *tier) key(addr netip.Addr, maxPrefixes int) netip.Prefix {
	bits := t.bits4
	if addr.Is6() {
		bits = t.bits6
	}

	prefix, _ := addr.Prefix(bits) // fails only for a length beyond the address's

	if _, known := t.counts[prefix]; !known && len(t.counts) >= maxPrefixes {
		return overflow
	}

	return prefix
}

// loginLimiter bounds the unauthenticated login starts — each stores a
// pending login for the transaction TTL — in fixed windows (simple; at
// most twice a budget across a window boundary), at two levels: a client
// (an IPv4 address, an IPv6 /64, one subscriber's allocation) gets a
// budget, and its network (an IPv4 /24, an IPv6 /48, which one party can
// own whole) networkShare times that budget. A start must fit in both, so
// that one network cannot fill the store: with the demo's limits it holds
// at most networkShare × 20 starts a minute × 10 minutes = 600 of the
// 10 000 pending logins.
//
// Each tier tracks at most maxPrefixes prefixes per window; the others
// share that tier's overflow budget, so a flood from more networks than
// that can exhaust it and refuse new clients until the next window — like
// a flood from enough networks to fill the store, which then answers 503
// until its transactions expire. Those are stopped at the edge, not here.
// Behind a reverse proxy every request comes from the proxy's address: key
// the limits on the client address your proxy forwards — only you know
// which proxy to trust — or rate-limit at the edge.
type loginLimiter struct {
	tiers       []*tier
	maxPrefixes int
	window      time.Duration
	now         func() time.Time

	mu    sync.Mutex
	start time.Time
}

func newLoginLimiter(perClient, maxPrefixes int, window time.Duration, now func() time.Time) *loginLimiter {
	return &loginLimiter{
		tiers: []*tier{
			{bits4: 32, bits6: 64, budget: perClient, counts: make(map[netip.Prefix]int)},
			{bits4: 24, bits6: 48, budget: networkShare * perClient, counts: make(map[netip.Prefix]int)},
		},
		maxPrefixes: maxPrefixes,
		window:      window,
		now:         now,
	}
}

// allow reports whether the peer at addr may start a login now and, if so,
// counts the start in every tier.
func (l *loginLimiter) allow(addr netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if now := l.now(); now.Sub(l.start) >= l.window {
		l.start = now

		for _, t := range l.tiers {
			clear(t.counts)
		}
	}

	keys := make([]netip.Prefix, len(l.tiers))

	for i, t := range l.tiers {
		keys[i] = t.key(addr, l.maxPrefixes)
		if t.counts[keys[i]] >= t.budget {
			return false
		}
	}

	for i, t := range l.tiers {
		t.counts[keys[i]]++
	}

	return true
}

// clientAddr is the peer address of a request, an IPv4-mapped address
// unmapped; the zero Addr — an unknown peer — when it does not parse.
func clientAddr(remoteAddr string) netip.Addr {
	peer, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return netip.Addr{}
	}

	return peer.Addr().Unmap()
}
