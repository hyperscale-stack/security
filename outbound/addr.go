// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"syscall"
)

// guard holds the validated policy shared by the transport, the dialer and
// the redirect check.
type guard struct {
	allowHTTP    bool
	allowed      []netip.Prefix
	checkURL     func(context.Context, *url.URL) error
	checkAddr    func(context.Context, netip.AddrPort) error
	maxRedirects int
	maxBytes     int64
}

// blockedIPv4 lists the IPv4 special-purpose blocks of the IANA registry
// (RFC 6890) that are not publicly routable, plus private and shared
// address space.
var blockedIPv4 = mustPrefixes(
	"0.0.0.0/8",       // "this network" (RFC 791); 0.0.0.0 reaches the local host on Linux
	"10.0.0.0/8",      // private (RFC 1918)
	"100.64.0.0/10",   // shared address space, CGNAT (RFC 6598)
	"127.0.0.0/8",     // loopback (RFC 1122)
	"169.254.0.0/16",  // link-local, cloud metadata (RFC 3927)
	"172.16.0.0/12",   // private (RFC 1918)
	"192.0.0.0/24",    // IETF protocol assignments (RFC 6890)
	"192.0.2.0/24",    // documentation TEST-NET-1 (RFC 5737)
	"192.88.99.0/24",  // deprecated 6to4 relay anycast (RFC 7526)
	"192.168.0.0/16",  // private (RFC 1918)
	"198.18.0.0/15",   // benchmarking (RFC 2544)
	"198.51.100.0/24", // documentation TEST-NET-2 (RFC 5737)
	"203.0.113.0/24",  // documentation TEST-NET-3 (RFC 5737)
	"224.0.0.0/4",     // multicast (RFC 5771)
	"240.0.0.0/4",     // reserved, limited broadcast (RFC 1112, RFC 919)
)

// globalIPv6 is the IPv6 global unicast space (RFC 4291 §2.4); an IPv6
// destination outside it, or inside reservedIPv6, is refused.
var globalIPv6 = netip.MustParsePrefix("2000::/3")

// reservedIPv6 lists the blocks of 2000::/3 that are not publicly routable
// hosts (IANA IPv6 special-purpose registry).
var reservedIPv6 = mustPrefixes(
	"2001::/23",     // IETF protocol assignments: Teredo, benchmarking, ORCHID… (RFC 2928)
	"2001:db8::/32", // documentation (RFC 3849)
	"2002::/16",     // 6to4, embeds an IPv4 address (RFC 3056)
	"3fff::/20",     // documentation (RFC 9637)
)

// nat64 is the well-known NAT64 prefix (RFC 6052): its addresses reach the
// IPv4 address embedded in their last 32 bits, which decides.
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

func mustPrefixes(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(cidrs))
	for i, c := range cidrs {
		out[i] = netip.MustParsePrefix(c)
	}

	return out
}

// containedIn reports whether addr lies in one of prefixes.
func containedIn(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}

	return false
}

// embeddedIPv4 returns the IPv4 address a 64:ff9b::/96 NAT64 address
// reaches.
func embeddedIPv4(addr netip.Addr) (netip.Addr, bool) {
	if !nat64.Contains(addr) {
		return netip.Addr{}, false
	}

	b := addr.As16()

	return netip.AddrFrom4([4]byte(b[12:16])), true
}

// blocked reports whether addr, an unzoned address, lies outside the
// publicly routable space: IPv4 (an IPv4-mapped address is judged as IPv4)
// on a deny-list, IPv6 on an allow-list, NAT64 on its embedded IPv4.
func blocked(addr netip.Addr) bool {
	addr = addr.Unmap()

	if addr.Is4() {
		return containedIn(blockedIPv4, addr)
	}

	if v4, ok := embeddedIPv4(addr); ok {
		return containedIn(blockedIPv4, v4)
	}

	return !globalIPv6.Contains(addr) || containedIn(reservedIPv6, addr)
}

// exempted reports whether addr, or the IPv4 address it reaches through
// NAT64, lies in an AllowedPrefixes entry.
func (g *guard) exempted(addr netip.Addr) bool {
	if containedIn(g.allowed, addr) {
		return true
	}

	v4, ok := embeddedIPv4(addr)

	return ok && containedIn(g.allowed, v4)
}

// checkAddress decides whether ap may be connected to. A zoned address is
// refused before anything else: netip.Prefix.Contains never matches one, so
// it would escape both the exemptions and the block list.
func (g *guard) checkAddress(ctx context.Context, ap netip.AddrPort) error {
	addr := ap.Addr()
	if addr.Zone() != "" {
		return fmt.Errorf("%w: scoped address", ErrDestinationNotAllowed)
	}

	addr = addr.Unmap()

	// The address is not named: the URL's host may be a tenant's, the
	// address it resolves to is the operator's business.
	if !g.exempted(addr) && blocked(addr) {
		return fmt.Errorf("%w: not publicly routable", ErrDestinationNotAllowed)
	}

	if g.checkAddr == nil {
		return nil
	}

	if err := g.checkAddr(ctx, netip.AddrPortFrom(addr, ap.Port())); err != nil {
		return fmt.Errorf("%w: %w", ErrDestinationNotAllowed, err)
	}

	return nil
}

// control is the net.Dialer.ControlContext hook: the dialer calls it with
// the resolved address it is about to connect to, so a name that resolves
// differently between two lookups (DNS rebinding) cannot slip past it.
func (g *guard) control(ctx context.Context, _, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: unparsable address", ErrDestinationNotAllowed)
	}

	return g.checkAddress(ctx, ap)
}

// dialContext dials with d. When the guard refuses the address, the error
// keeps its cause but drops the resolved address net.Dialer puts in its
// *net.OpError, so that the error of a request to a tenant-supplied URL
// does not disclose the internal address the name resolved to.
func dialContext(d *net.Dialer) func(ctx context.Context, network, address string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := d.DialContext(ctx, network, address)
		if err == nil || !errors.Is(err, ErrDestinationNotAllowed) {
			return conn, err //nolint:wrapcheck // the round tripper wraps transport errors
		}

		cause := ErrDestinationNotAllowed

		var opErr *net.OpError
		if errors.As(err, &opErr) {
			cause = opErr.Err
		}

		return nil, &net.OpError{Op: "dial", Net: network, Err: cause}
	}
}
