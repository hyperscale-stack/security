// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package outbound

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBlocked walks the IANA IPv4 and IPv6 special-purpose registries
// (RFC 6890) and the boundaries of every range: an address is allowed only
// when it is publicly routable.
func TestBlocked(t *testing.T) {
	t.Parallel()

	cases := []struct {
		addr    string
		blocked bool
	}{
		// IPv4 deny-list.
		{"0.0.0.0", true},          // "this network" (RFC 791): connects to the local host on Linux
		{"0.255.255.255", true},    // end of 0.0.0.0/8
		{"10.0.0.1", true},         // RFC 1918
		{"10.255.255.255", true},   // end of 10/8
		{"11.0.0.1", false},        // just after 10/8
		{"9.255.255.255", false},   // just before 10/8
		{"100.63.255.255", false},  // just before the RFC 6598 shared space
		{"100.64.0.0", true},       // RFC 6598 (CGNAT), also Alibaba metadata 100.100.100.200
		{"100.100.100.200", true},  // Alibaba Cloud metadata
		{"100.127.255.255", true},  // end of 100.64/10
		{"100.128.0.0", false},     // just after 100.64/10
		{"127.0.0.1", true},        // loopback
		{"127.255.255.254", true},  // loopback
		{"169.254.169.254", true},  // link-local, cloud metadata
		{"172.15.255.255", false},  // just before 172.16/12
		{"172.16.0.1", true},       // RFC 1918
		{"172.31.255.255", true},   // end of 172.16/12
		{"172.32.0.0", false},      // just after 172.16/12
		{"192.0.0.1", true},        // IETF protocol assignments
		{"192.0.0.170", true},      // NAT64 discovery
		{"192.0.0.192", true},      // OCI metadata
		{"192.0.1.1", false},       // just after 192.0.0.0/24
		{"192.0.2.1", true},        // TEST-NET-1
		{"192.88.99.1", true},      // deprecated 6to4 relay anycast
		{"192.168.1.1", true},      // RFC 1918
		{"192.169.0.1", false},     // just after 192.168/16
		{"198.17.255.255", false},  // just before benchmarking
		{"198.18.0.1", true},       // benchmarking
		{"198.19.255.255", true},   // end of 198.18/15
		{"198.20.0.0", false},      // just after 198.18/15
		{"198.51.100.7", true},     // TEST-NET-2
		{"203.0.113.9", true},      // TEST-NET-3
		{"224.0.0.1", true},        // multicast
		{"239.255.255.255", true},  // multicast
		{"240.0.0.1", true},        // reserved
		{"255.255.255.255", true},  // limited broadcast
		{"223.255.255.255", false}, // last unicast before multicast
		{"1.1.1.1", false},
		{"8.8.8.8", false},

		// IPv6 allow-list: 2000::/3 minus the special-purpose blocks.
		{"::", true},               // unspecified
		{"::1", true},              // loopback
		{"::7f00:1", true},         // deprecated IPv4-compatible 127.0.0.1
		{"::ffff:0:7f00:1", true},  // SIIT IPv4-translated (RFC 2765), neither ::/96 nor mapped
		{"64:ff9b:1::1", true},     // local-use NAT64 (RFC 8215)
		{"100::1", true},           // discard-only (RFC 6666)
		{"100:0:0:1::1", true},     // dummy IPv6 prefix (RFC 9780)
		{"2001::1", true},          // Teredo, in 2001::/23
		{"2001:2::1", true},        // benchmarking, in 2001::/23
		{"2001:1ff:ffff::1", true}, // end of 2001::/23
		{"2001:200::1", false},     // just after 2001::/23
		{"2001:db8::1", true},      // documentation
		{"2002:7f00:1::1", true},   // 6to4 of 127.0.0.1
		{"3fff::1", true},          // documentation (RFC 9637)
		{"4000::1", true},          // outside 2000::/3
		{"1fff:ffff::1", true},     // just before 2000::/3
		{"5f00::1", true},          // SRv6 SIDs
		{"fc00::1", true},          // unique local
		{"fd00:ec2::254", true},    // AWS IMDS over IPv6
		{"fe80::1", true},          // link-local
		{"fec0::1", true},          // deprecated site-local
		{"ff02::1", true},          // multicast
		{"2606:4700:4700::1111", false},
		{"2001:4860:4860::8888", false},
		{"2a00:1450:4007::1", false},
		{"3ffe:ffff::1", false}, // inside 2000::/3, outside 3fff::/20

		// NAT64 well-known prefix (RFC 6052): judged on the embedded IPv4.
		{"64:ff9b::808:808", false}, // 8.8.8.8
		{"64:ff9b::7f00:1", true},   // 127.0.0.1
		{"64:ff9b::a00:1", true},    // 10.0.0.1
		{"64:ff9b::a9fe:a9fe", true},

		// IPv4-mapped addresses are judged as IPv4.
		{"::ffff:8.8.8.8", false},
		{"::ffff:127.0.0.1", true},
	}

	for _, c := range cases {
		t.Run(c.addr, func(t *testing.T) {
			t.Parallel()

			addr := netip.MustParseAddr(c.addr)
			assert.Equal(t, c.blocked, blocked(addr), "blocked(%s)", c.addr)
		})
	}
}

// TestCheckAddress covers the steps around the classification: zones are
// refused first, IPv4-mapped addresses are judged as IPv4, AllowedPrefixes
// exempt (including the IPv4 embedded in a NAT64 address), and CheckAddr
// sees the normalized address and can only restrict.
func TestCheckAddress(t *testing.T) {
	t.Parallel()

	loopback := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}

	cases := []struct {
		name    string
		allowed []netip.Prefix
		addr    string
		wantErr bool
	}{
		{"public", nil, "8.8.8.8:443", false},
		{"loopback blocked", nil, "127.0.0.1:443", true},
		{"loopback exempted", loopback, "127.0.0.1:443", false},
		{"v6 loopback exempted", loopback, "[::1]:443", false},
		{"mapped loopback blocked", nil, "[::ffff:127.0.0.1]:443", true},
		{"mapped loopback exempted as IPv4", loopback, "[::ffff:127.0.0.1]:443", false},
		{"mapped metadata blocked", nil, "[::ffff:169.254.169.254]:80", true},
		{"mapped public allowed", nil, "[::ffff:8.8.8.8]:443", false},
		{"zoned link-local blocked", nil, "[fe80::1%eth0]:443", true},
		{"zoned link-local never exempted", []netip.Prefix{netip.MustParsePrefix("fe80::/10")}, "[fe80::1%eth0]:443", true},
		{"zoned global blocked", nil, "[2606:4700::1%eth0]:443", true},
		{"zoned mapped loopback never exempted", loopback, "[::ffff:127.0.0.1%lo]:443", true},
		{"nat64 private blocked", nil, "[64:ff9b::a00:1]:443", true},
		{"nat64 embedded exempted", []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, "[64:ff9b::a00:1]:443", false},
		{"private exempted subnet", []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}, "10.20.1.2:443", false},
		{"private outside exempted subnet", []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}, "10.21.1.2:443", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			g := &guard{allowed: c.allowed}
			err := g.checkAddress(context.Background(), netip.MustParseAddrPort(c.addr))

			if c.wantErr {
				require.ErrorIs(t, err, ErrDestinationNotAllowed)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestCheckAddressHook checks that CheckAddr receives the unmapped, unzoned
// address, can refuse it, and is never consulted for an address the
// built-in policy already refused.
func TestCheckAddressHook(t *testing.T) {
	t.Parallel()

	errDenied := errors.New("denied by app")

	var seen []netip.AddrPort

	g := &guard{
		allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		checkAddr: func(_ context.Context, ap netip.AddrPort) error {
			seen = append(seen, ap)
			if ap.Addr() == netip.MustParseAddr("8.8.4.4") {
				return errDenied
			}

			return nil
		},
	}

	require.NoError(t, g.checkAddress(context.Background(), netip.MustParseAddrPort("[::ffff:127.0.0.1]:8443")))

	err := g.checkAddress(context.Background(), netip.MustParseAddrPort("8.8.4.4:443"))
	require.ErrorIs(t, err, ErrDestinationNotAllowed)
	require.ErrorIs(t, err, errDenied)

	require.Error(t, g.checkAddress(context.Background(), netip.MustParseAddrPort("10.0.0.1:443")))

	require.Equal(t, []netip.AddrPort{
		netip.MustParseAddrPort("127.0.0.1:8443"),
		netip.MustParseAddrPort("8.8.4.4:443"),
	}, seen, "the hook sees unmapped addresses, and never a blocked one")
}

// TestCheckDialAddress checks the adapter used as net.Dialer.ControlContext:
// an address it cannot parse is refused.
func TestCheckDialAddress(t *testing.T) {
	t.Parallel()

	g := &guard{}

	require.ErrorIs(t, g.control(context.Background(), "tcp4", "not-an-address", nil), ErrDestinationNotAllowed)
	require.ErrorIs(t, g.control(context.Background(), "tcp4", "127.0.0.1:443", nil), ErrDestinationNotAllowed)
	require.NoError(t, g.control(context.Background(), "tcp4", "8.8.8.8:443", nil))
}

// chunkReader returns its data one byte per Read.
type chunkReader struct {
	data   []byte
	closed bool
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}

	if len(p) == 0 {
		return 0, nil
	}

	p[0] = r.data[0]
	r.data = r.data[1:]

	return 1, nil
}

func (r *chunkReader) Close() error {
	r.closed = true

	return nil
}

func TestLimitedBody(t *testing.T) {
	t.Parallel()

	t.Run("exactly the limit", func(t *testing.T) {
		t.Parallel()

		src := &chunkReader{data: []byte("abc")}
		b := &limitedBody{body: src, remaining: 3}

		got, err := io.ReadAll(b)
		require.NoError(t, err)
		assert.Equal(t, "abc", string(got))
		require.NoError(t, b.Close())
		assert.True(t, src.closed)
	})

	t.Run("one byte over", func(t *testing.T) {
		t.Parallel()

		b := &limitedBody{body: &chunkReader{data: []byte("abcd")}, remaining: 3}

		got, err := io.ReadAll(b)
		require.ErrorIs(t, err, ErrResponseTooLarge)
		assert.Equal(t, "abc", string(got))

		n, err := b.Read(make([]byte, 8))
		assert.Zero(t, n)
		require.ErrorIs(t, err, ErrResponseTooLarge, "stays failed")
	})

	t.Run("large read buffer", func(t *testing.T) {
		t.Parallel()

		b := &limitedBody{body: io.NopCloser(strings.NewReader("abcdef")), remaining: 4}

		buf := make([]byte, 64)
		n, err := b.Read(buf)
		require.ErrorIs(t, err, ErrResponseTooLarge)
		assert.Equal(t, "abcd", string(buf[:n]))
	})

	t.Run("empty read", func(t *testing.T) {
		t.Parallel()

		b := &limitedBody{body: &chunkReader{data: []byte("a")}, remaining: 0}

		n, err := b.Read(nil)
		require.NoError(t, err)
		assert.Zero(t, n)
	})
}
