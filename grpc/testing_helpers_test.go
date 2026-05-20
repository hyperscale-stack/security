// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grpcsec_test

import (
	"context"
	"net"
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/test/bufconn"
)

// The tests reuse the standard gRPC health service (grpc_health_v1) as the
// guinea-pig service: Check is a unary RPC and Watch is a server stream,
// so both interceptor kinds are exercised without generating any protobuf.

// dialBufconn starts an in-memory gRPC server with the given interceptors,
// registers the health service, and returns a connected client. Everything
// is torn down via t.Cleanup.
func dialBufconn(
	t *testing.T,
	unary grpc.UnaryServerInterceptor,
	stream grpc.StreamServerInterceptor,
) healthpb.HealthClient {
	t.Helper()

	lis := bufconn.Listen(1 << 20)

	var serverOpts []grpc.ServerOption
	if unary != nil {
		serverOpts = append(serverOpts, grpc.UnaryInterceptor(unary))
	}

	if stream != nil {
		serverOpts = append(serverOpts, grpc.StreamInterceptor(stream))
	}

	srv := grpc.NewServer(serverOpts...)
	healthpb.RegisterHealthServer(srv, health.NewServer())

	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = conn.Close()
		srv.Stop()
		_ = lis.Close()
	})

	return healthpb.NewHealthClient(conn)
}

// --- fakes mirroring the core test doubles ------------------------------

type fakePrincipal struct{ sub string }

func (p fakePrincipal) Subject() string { return p.sub }

type fakeAuth struct {
	pr            security.Principal
	authorities   []string
	authenticated bool
}

func newAuth(sub string, authorities ...string) fakeAuth {
	return fakeAuth{pr: fakePrincipal{sub: sub}, authorities: authorities, authenticated: true}
}

func (a fakeAuth) Principal() security.Principal { return a.pr }
func (a fakeAuth) Credentials() any              { return nil }
func (a fakeAuth) Authorities() []string         { return a.authorities }
func (a fakeAuth) IsAuthenticated() bool         { return a.authenticated }
func (a fakeAuth) Name() string                  { return a.pr.Subject() }

// tokenExtractor reads the "authorization" metadata key and produces a
// pending bearer-like authentication carrying the raw token.
type tokenExtractor struct{}

func (tokenExtractor) Extract(_ context.Context, c security.Carrier) (security.Authentication, error) {
	v := c.Get("authorization")
	if v == "" {
		return nil, nil
	}

	const prefix = "Bearer "
	if len(v) <= len(prefix) {
		return nil, nil
	}

	return pendingAuth{token: v[len(prefix):]}, nil
}

// pendingAuth is the un-validated authentication produced by tokenExtractor.
type pendingAuth struct{ token string }

func (a pendingAuth) Principal() security.Principal { return security.AnonymousPrincipal }
func (a pendingAuth) Credentials() any              { return a.token }
func (a pendingAuth) Authorities() []string         { return nil }
func (a pendingAuth) IsAuthenticated() bool         { return false }
func (a pendingAuth) Name() string                  { return "pending" }

// tokenAuthenticator accepts the magic token "letmein" and rejects the rest.
type tokenAuthenticator struct{ authorities []string }

func (tokenAuthenticator) Supports(a security.Authentication) bool {
	_, ok := a.(pendingAuth)

	return ok
}

func (ta tokenAuthenticator) Authenticate(_ context.Context, a security.Authentication) (security.Authentication, error) {
	p, ok := a.(pendingAuth)
	if !ok {
		return a, security.ErrUnsupportedCredential
	}

	if p.token != "letmein" {
		return a, security.ErrInvalidCredentials
	}

	return newAuth("alice", ta.authorities...), nil
}
