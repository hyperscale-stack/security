// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient_test

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// HTTP/2 frame types and flags (RFC 9113 §6) the GOAWAY server uses.
const (
	frameData     = 0x0
	frameHeaders  = 0x1
	frameSettings = 0x4
	frameGoAway   = 0x7
	flagAck       = 0x1
	flagEndHeader = 0x4
)

// goAwayServer starts a raw HTTP/2 server that answers every request with
// 200 application/json and the beginning of a body, then sends a GOAWAY
// frame carrying debug and closes the connection: the client's body read
// fails with an error quoting the debug data (Go's http2.GoAwayError). It
// returns the server's URL; its certificate is httptest's.
func goAwayServer(t *testing.T, debug []byte) string {
	t.Helper()

	cert := httptest.NewTLSServer(nil)
	t.Cleanup(cert.Close)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: cert.TLS.Certificates, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}

			go serveGoAway(conn, debug)
		}
	}()

	return "https://" + ln.Addr().String()
}

// serveGoAway runs one HTTP/2 connection of goAwayServer.
func serveGoAway(conn net.Conn, debug []byte) {
	defer func() { _ = conn.Close() }()

	r := bufio.NewReader(conn)
	if _, err := io.ReadFull(r, make([]byte, 24)); err != nil { // the client connection preface
		return
	}

	writeFrame(conn, frameSettings, 0, 0, nil)

	for {
		header := make([]byte, 9)
		if _, err := io.ReadFull(r, header); err != nil {
			return
		}

		length := int(header[0])<<16 | int(header[1])<<8 | int(header[2])
		if _, err := io.CopyN(io.Discard, r, int64(length)); err != nil {
			return
		}

		typ, flags, stream := header[3], header[4], binary.BigEndian.Uint32(header[5:])

		switch {
		case typ == frameSettings && flags&flagAck == 0:
			writeFrame(conn, frameSettings, flagAck, 0, nil)
		case typ == frameHeaders:
			// HPACK: :status 200 (static index 8), content-type (index 31)
			// with a 16-byte literal value.
			block := append([]byte{0x88, 0x0f, 0x10, 0x10}, "application/json"...)
			writeFrame(conn, frameHeaders, flagEndHeader, stream, block)
			writeFrame(conn, frameData, 0, stream, []byte(`{"a":`))

			goAway := make([]byte, 8, 8+len(debug))
			binary.BigEndian.PutUint32(goAway, stream)
			binary.BigEndian.PutUint32(goAway[4:], 0x2) // INTERNAL_ERROR
			writeFrame(conn, frameGoAway, 0, 0, append(goAway, debug...))

			return
		}
	}
}

// writeFrame writes one HTTP/2 frame (RFC 9113 §4.1).
func writeFrame(w io.Writer, typ, flags byte, stream uint32, payload []byte) {
	header := make([]byte, 9, 9+len(payload))
	header[0], header[1], header[2] = byte(len(payload)>>16), byte(len(payload)>>8), byte(len(payload))
	header[3], header[4] = typ, flags
	binary.BigEndian.PutUint32(header[5:], stream)
	_, _ = w.Write(append(header, payload...))
}
