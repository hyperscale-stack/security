// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package outbound

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	dnsTypeA    = 1
	dnsTypeAAAA = 28
)

// rebindingDNS is an in-process DNS server whose answers change between
// resolutions, like a DNS-rebinding attacker's: the first A and AAAA
// queries get first4/first6, every later one gets later4/later6 (nil = no
// record of that type).
type rebindingDNS struct {
	first4, later4 []byte
	first6, later6 []byte
	aQueries       atomic.Int64
	aaaaQueries    atomic.Int64
}

func (d *rebindingDNS) resolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			client, srv := net.Pipe()
			go d.serve(srv)

			return client, nil
		},
	}
}

// serve answers one length-prefixed (stream) DNS query: net.Pipe is not a
// PacketConn, so the Go resolver frames its messages as over TCP.
func (d *rebindingDNS) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return
	}

	msg := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(conn, msg); err != nil {
		return
	}

	resp := d.answer(msg)

	out := binary.BigEndian.AppendUint16(nil, uint16(len(resp))) //nolint:gosec // tiny test message
	_, _ = conn.Write(append(out, resp...))
}

func (d *rebindingDNS) answer(query []byte) []byte {
	off := 12
	for query[off] != 0 {
		off += int(query[off]) + 1
	}

	off++ // root label
	qtype := binary.BigEndian.Uint16(query[off : off+2])
	question := query[12 : off+4]

	var rdata []byte

	switch qtype {
	case dnsTypeA:
		rdata = d.later4
		if d.aQueries.Add(1) == 1 {
			rdata = d.first4
		}
	case dnsTypeAAAA:
		rdata = d.later6
		if d.aaaaQueries.Add(1) == 1 {
			rdata = d.first6
		}
	}

	resp := append([]byte{}, query[0:2]...)     // ID
	resp = append(resp, 0x81, 0x80)             // response, recursion desired + available, NOERROR
	resp = append(resp, 0, 1, 0, 0, 0, 0, 0, 0) // QDCOUNT=1, ANCOUNT set below, NSCOUNT=0, ARCOUNT=0
	resp = append(resp, question...)

	if rdata != nil {
		resp[7] = 1
		resp = append(resp, 0xC0, 0x0C)                                // name: pointer to the question
		resp = binary.BigEndian.AppendUint16(resp, qtype)              // type
		resp = append(resp, 0, 1, 0, 0, 0, 0)                          // class IN, TTL 0
		resp = binary.BigEndian.AppendUint16(resp, uint16(len(rdata))) //nolint:gosec // 4 or 16
		resp = append(resp, rdata...)
	}

	return resp
}

// TestDialCheckSeesTheResolvedAddress proves the address policy runs on the
// address actually connected to, after the one resolution the dialer makes.
// The name first resolves to ::1 (exempted) and afterwards to 127.0.0.1,
// where the target listens: an implementation checking a separate lookup
// before dialing would approve ::1, then connect to 127.0.0.1.
func TestDialCheckSeesTheResolvedAddress(t *testing.T) {
	t.Parallel()

	var hits atomic.Int64

	s := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	t.Cleanup(s.Close)

	port := strconv.Itoa(s.Listener.Addr().(*net.TCPAddr).Port)

	t.Run("exempted first answer, private later answer", func(t *testing.T) {
		t.Parallel()

		dns := &rebindingDNS{first6: net.IPv6loopback, later4: net.IPv4(127, 0, 0, 1).To4()}

		client, err := newClient(Policy{
			AllowHTTP:       true,
			AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("::1/128")},
		}, dns.resolver())
		require.NoError(t, err)

		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://rebind.test:"+port+"/", nil)
		require.NoError(t, err)

		_, err = client.Do(req)
		require.Error(t, err, "[::1] has no listener: the connection fails")
		assert.Equal(t, int64(1), dns.aQueries.Load(), "one resolution only")
		assert.Equal(t, int64(1), dns.aaaaQueries.Load(), "one resolution only")
	})

	t.Run("blocked first answer", func(t *testing.T) {
		t.Parallel()

		dns := &rebindingDNS{first4: net.IPv4(127, 0, 0, 1).To4()}

		client, err := newClient(Policy{AllowHTTP: true}, dns.resolver())
		require.NoError(t, err)

		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://rebind.test:"+port+"/", nil)
		require.NoError(t, err)

		_, err = client.Do(req)
		require.ErrorIs(t, err, ErrDestinationNotAllowed)
	})

	t.Cleanup(func() { assert.Zero(t, hits.Load(), "the 127.0.0.1 listener is never reached") })
}
