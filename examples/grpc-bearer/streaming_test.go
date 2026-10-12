// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// Audit CORE-05 (probe TestZZAuditStreamingRPCUnauthenticated): the example
// chained only unary interceptors, so the server-streaming Health.Watch RPC
// was served to callers without any token.
func TestGRPCBearerAuthenticatesAndAuthorizesStreamingRPCs(t *testing.T) {
	t.Parallel()

	srv, mint, err := newServer()
	require.NoError(t, err)

	lis := bufconn.Listen(1 << 20)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	client := healthpb.NewHealthClient(conn)

	good, err := mint(scope)
	require.NoError(t, err)

	wrongScope, err := mint("other:read")
	require.NoError(t, err)

	watch := func(t *testing.T, token string) (codes.Code, *healthpb.HealthCheckResponse) {
		t.Helper()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		t.Cleanup(cancel)

		if token != "" {
			ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
		}

		stream, err := client.Watch(ctx, &healthpb.HealthCheckRequest{})
		require.NoError(t, err)

		msg, err := stream.Recv()

		return status.Code(err), msg
	}

	t.Run("without token", func(t *testing.T) {
		t.Parallel()

		code, _ := watch(t, "")
		assert.Equal(t, codes.Unauthenticated, code)
	})

	t.Run("without the scope", func(t *testing.T) {
		t.Parallel()

		code, _ := watch(t, wrongScope)
		assert.Equal(t, codes.PermissionDenied, code)
	})

	t.Run("with the scope", func(t *testing.T) {
		t.Parallel()

		code, msg := watch(t, good)
		require.Equal(t, codes.OK, code)
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, msg.GetStatus())
	})
}
