// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"net"
	"testing"

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

func TestGRPCBearerExample(t *testing.T) {
	t.Parallel()

	srv, mint, err := newServer()
	require.NoError(t, err)

	lis := bufconn.Listen(1 << 20)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	client := healthpb.NewHealthClient(conn)

	goodToken, err := mint(scope)
	require.NoError(t, err)

	wrongScopeToken, err := mint("other:read")
	require.NoError(t, err)

	check := func(t *testing.T, token string) error {
		t.Helper()

		ctx := context.Background()
		if token != "" {
			ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
		}

		_, err := client.Check(ctx, &healthpb.HealthCheckRequest{})

		return err
	}

	t.Run("valid token with the right scope succeeds", func(t *testing.T) {
		t.Parallel()
		assert.NoError(t, check(t, goodToken))
	})

	t.Run("missing token is unauthenticated", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, codes.Unauthenticated, status.Code(check(t, "")))
	})

	t.Run("garbage token is unauthenticated", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, codes.Unauthenticated, status.Code(check(t, "not-a-jwt")))
	})

	t.Run("valid token without the scope is permission-denied", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, codes.PermissionDenied, status.Code(check(t, wrongScopeToken)))
	})
}
