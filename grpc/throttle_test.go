// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grpcsec_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/hyperscale-stack/security"
	grpcsec "github.com/hyperscale-stack/security/grpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// throttlingAuthenticator refuses every attempt as a limiter would.
type throttlingAuthenticator struct{}

func (throttlingAuthenticator) Supports(security.Authentication) bool { return true }

func (throttlingAuthenticator) Authenticate(context.Context, security.Authentication) (security.Authentication, error) {
	return security.Anonymous(), fmt.Errorf("basic: %w", &security.TooManyAttemptsError{RetryAfter: time.Minute})
}

// A throttled attempt is ResourceExhausted ("Some resource has been
// exhausted, perhaps a per-user quota"), with a fixed message.
func TestDefaultErrorMapperAnswersAThrottleResourceExhausted(t *testing.T) {
	t.Parallel()

	mapper := grpcsec.DefaultErrorMapper()

	for _, err := range []error{
		security.ErrTooManyAttempts,
		&security.TooManyAttemptsError{RetryAfter: time.Minute},
		errors.Join(security.ErrInvalidCredentials, &security.TooManyAttemptsError{}),
	} {
		st := status.Convert(mapper.Map(context.Background(), err))

		assert.Equal(t, codes.ResourceExhausted, st.Code())
		assert.Equal(t, "too many attempts", st.Message())
	}
}

func TestInterceptorsAnswerAThrottledRPC(t *testing.T) {
	t.Parallel()

	engine := security.NewEngine(security.NewManager(throttlingAuthenticator{}), tokenExtractor{})
	client := dialWithOptions(t, grpcsec.ServerOptions(engine)...)

	_, err := client.Check(bearer(context.Background(), "letmein"), &healthpb.HealthCheckRequest{})
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))

	stream, err := client.Watch(bearer(context.Background(), "letmein"), &healthpb.HealthCheckRequest{})
	if err == nil {
		_, err = stream.Recv()
	}

	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
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

// alwaysExtractor extracts a pending credential from every RPC.
type alwaysExtractor struct{}

func (alwaysExtractor) Extract(context.Context, security.Carrier) (security.Authentication, error) {
	return pendingAuth{token: "x"}, nil
}

// peerStream is a grpc.ServerStream carrying ctx.
type peerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s peerStream) Context() context.Context { return s.ctx }

// The interceptors supply the transport peer as the client address an
// AttemptLimiter keys on, unless an interceptor before them stored one.
func TestInterceptorsSupplyTheClientAddress(t *testing.T) {
	t.Parallel()

	tcpPeer := func(ip string) context.Context {
		return peer.NewContext(bearer(context.Background(), "x"), &peer.Peer{
			Addr: &net.TCPAddr{IP: net.ParseIP(ip), Port: 50051},
		})
	}

	cases := []struct {
		name  string
		ctx   context.Context
		want  netip.Addr
		found bool
	}{
		{"IPv4 peer", tcpPeer("203.0.113.7"), netip.MustParseAddr("203.0.113.7"), true},
		{"IPv6 peer", tcpPeer("2001:db8::7"), netip.MustParseAddr("2001:db8::7"), true},
		{"Unix socket peer", peer.NewContext(context.Background(), &peer.Peer{Addr: &net.UnixAddr{Name: "@", Net: "unix"}}),
			netip.Addr{}, false},
		{"no peer", context.Background(), netip.Addr{}, false},
		// Review m3 (mutant G10): a peer without address must not panic —
		// grpc-go recovers no panic.
		{"peer without address", peer.NewContext(context.Background(), &peer.Peer{}), netip.Addr{}, false},
		// Review m4: forwarded metadata is client input, never trusted.
		{"forwarded metadata ignored", metadata.NewIncomingContext(tcpPeer("203.0.113.7"),
			metadata.Pairs("x-forwarded-for", "192.0.2.66", "x-real-ip", "192.0.2.67")), netip.MustParseAddr("203.0.113.7"), true},
		{"set upstream", security.WithClientAddr(tcpPeer("203.0.113.7"), netip.MustParseAddr("192.0.2.44")),
			netip.MustParseAddr("192.0.2.44"), true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			unary, stream := &addrSpy{}, &addrSpy{}

			unaryEngine := security.NewEngine(security.NewManager(unary), alwaysExtractor{})
			_, err := grpcsec.UnaryServerInterceptor(unaryEngine)(c.ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/x/Y"},
				func(context.Context, any) (any, error) { return "ok", nil })
			require.NoError(t, err)

			streamEngine := security.NewEngine(security.NewManager(stream), alwaysExtractor{})
			err = grpcsec.StreamServerInterceptor(streamEngine)(nil, peerStream{ctx: c.ctx}, &grpc.StreamServerInfo{FullMethod: "/x/Y"},
				func(any, grpc.ServerStream) error { return nil })
			require.NoError(t, err)

			for _, spy := range []*addrSpy{unary, stream} {
				assert.Equal(t, c.found, spy.found)
				assert.Equal(t, c.want, spy.addr)
			}
		})
	}
}
