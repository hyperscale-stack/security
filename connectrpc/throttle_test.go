// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package connectrpcsec_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/hyperscale-stack/security"
	connectrpcsec "github.com/hyperscale-stack/security/connectrpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A throttled attempt is ResourceExhausted — HTTP 429 in the Connect
// protocol — with Retry-After (RFC 6585 §4, RFC 9110 §10.2.3) and
// Cache-Control: no-store in the error metadata, which a unary call sends
// as response headers. Its credentials were not checked: a Bearer
// challenge carries no error code.
func TestDefaultErrorMapperAnswersAThrottleResourceExhausted(t *testing.T) {
	t.Parallel()

	throttled := &security.TooManyAttemptsError{RetryAfter: 59*time.Second + time.Millisecond}

	cases := []struct {
		name       string
		scheme     string
		err        error
		retryAfter string
		challenge  []string
	}{
		{"bearer", "", throttled, "60", []string{bearerAPI}},
		{"basic", "Basic", throttled, "60", nil},
		{"delay unknown", "", security.ErrTooManyAttempts, "", []string{bearerAPI}},
		{"joined", "", errors.Join(security.ErrInvalidCredentials, throttled), "60", []string{bearerAPI}},
		// Review m3 (mutant K10): an unknown delay sends no Retry-After.
		{"zero delay", "", &security.TooManyAttemptsError{}, "", []string{bearerAPI}},
		{"negative delay", "", &security.TooManyAttemptsError{RetryAfter: -time.Second}, "", []string{bearerAPI}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			// The mapper alone, without the interceptors' bearer flag: the
			// interceptor test below covers a request carrying a token.
			ctx := context.Background()
			got := connectrpcsec.DefaultErrorMapper(c.scheme, "").Map(ctx, c.err)

			var ce *connect.Error

			require.ErrorAs(t, got, &ce)
			assert.Equal(t, connect.CodeResourceExhausted, ce.Code())
			assert.Equal(t, "too many attempts", ce.Message())
			assert.Equal(t, c.retryAfter, ce.Meta().Get("Retry-After"))
			assert.Equal(t, "no-store", ce.Meta().Get("Cache-Control"))
			assert.Equal(t, c.challenge, ce.Meta().Values("WWW-Authenticate"))
		})
	}
}

func TestInterceptorChallengesAThrottledBearerRequestWithoutACode(t *testing.T) {
	t.Parallel()

	engine := security.NewEngine(security.NewManager(throttling{}), tokenExtractor{})
	interceptor := connectrpcsec.NewAuthenticationInterceptor(engine)

	_, err := interceptor.WrapUnary((&recordingUnary{}).fn)(context.Background(), unaryReq("letmein"))

	var ce *connect.Error

	require.ErrorAs(t, err, &ce)
	assert.Equal(t, connect.CodeResourceExhausted, ce.Code())
	assert.Equal(t, []string{bearerAPI}, ce.Meta().Values("WWW-Authenticate"))
	assert.Equal(t, "60", ce.Meta().Get("Retry-After"))
}

// throttling refuses every attempt as a limiter would.
type throttling struct{}

func (throttling) Supports(security.Authentication) bool { return true }

func (throttling) Authenticate(context.Context, security.Authentication) (security.Authentication, error) {
	return security.Anonymous(), &security.TooManyAttemptsError{RetryAfter: time.Minute}
}

// addrSpy records the client address its authentication context carried.
type addrSpy struct {
	addr  netip.Addr
	found bool
}

func (s *addrSpy) Supports(security.Authentication) bool { return true }

func (s *addrSpy) Authenticate(ctx context.Context, _ security.Authentication) (security.Authentication, error) {
	s.addr, s.found = security.ClientAddrFromContext(ctx)

	return newAuth("alice"), nil
}

// peerRequest is a server-side unary request from peer.
type peerRequest struct {
	*connect.Request[struct{}]

	peer string
}

func (r peerRequest) Peer() connect.Peer { return connect.Peer{Addr: r.peer} }

// peerConn is a streaming connection from peer.
type peerConn struct {
	*fakeStreamingHandlerConn

	peer string
}

func (c peerConn) Peer() connect.Peer { return connect.Peer{Addr: c.peer} }

// The interceptor supplies the peer as the client address an
// AttemptLimiter keys on, unless an interceptor before it stored one.
func TestInterceptorSuppliesTheClientAddress(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		peer      string
		upstream  *netip.Addr
		forwarded bool
		want      netip.Addr
		found     bool
	}{
		{"IPv4 peer", "203.0.113.7:443", nil, false, netip.MustParseAddr("203.0.113.7"), true},
		{"IPv6 peer", "[2001:db8::7]:443", nil, false, netip.MustParseAddr("2001:db8::7"), true},
		{"no peer", "", nil, false, netip.Addr{}, false},
		{"set upstream", "203.0.113.7:443", new(netip.MustParseAddr("192.0.2.44")), false, netip.MustParseAddr("192.0.2.44"), true},
		// Review m4: forwarded headers are client input, never trusted.
		{"forwarded headers ignored", "203.0.113.7:443", nil, true, netip.MustParseAddr("203.0.113.7"), true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			if c.upstream != nil {
				ctx = security.WithClientAddr(ctx, *c.upstream)
			}

			unary, stream := &addrSpy{}, &addrSpy{}

			req := connect.NewRequest(&struct{}{})
			req.Header().Set("Authorization", "Bearer letmein")

			if c.forwarded {
				req.Header().Set("X-Forwarded-For", "192.0.2.66")
				req.Header().Set("Forwarded", "for=192.0.2.68")
			}

			_, err := connectrpcsec.NewAuthenticationInterceptor(
				security.NewEngine(security.NewManager(unary), tokenExtractor{}),
			).WrapUnary((&recordingUnary{}).fn)(ctx, peerRequest{Request: req, peer: c.peer})
			require.NoError(t, err)

			conn := peerConn{fakeStreamingHandlerConn: newStreamConn(nil), peer: c.peer}
			conn.reqHdr.Set("Authorization", "Bearer letmein")

			if c.forwarded {
				conn.reqHdr.Set("X-Forwarded-For", "192.0.2.66")
			}

			err = connectrpcsec.NewAuthenticationInterceptor(
				security.NewEngine(security.NewManager(stream), tokenExtractor{}),
			).WrapStreamingHandler((&recordingStream{}).fn)(ctx, conn)
			require.NoError(t, err)

			for _, spy := range []*addrSpy{unary, stream} {
				assert.Equal(t, c.found, spy.found)
				assert.Equal(t, c.want, spy.addr)
			}
		})
	}
}
