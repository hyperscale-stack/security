// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grpcsec_test

import (
	"context"
	"testing"

	"github.com/hyperscale-stack/security"
	grpcsec "github.com/hyperscale-stack/security/grpc"
	"github.com/hyperscale-stack/security/voter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

// chainUnary composes two unary interceptors (authenticate then authorize)
// so the authorisation step sees the context the authentication step
// produced — mirroring how applications wire grpc.ChainUnaryInterceptor.
func chainUnary(a, b grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		return a(ctx, req, info, func(ctx context.Context, req any) (any, error) {
			return b(ctx, req, info, handler)
		})
	}
}

func TestUnaryAuthorizeGrantsWhenRolePresent(t *testing.T) {
	t.Parallel()

	adm := security.NewAffirmativeDecisionManager(voter.HasRole("ADMIN"))

	interceptor := chainUnary(
		grpcsec.UnaryServerInterceptor(newEngine("ROLE_ADMIN")),
		grpcsec.UnaryAuthorize(adm, []security.Attribute{security.Role("ADMIN")}),
	)

	client := dialBufconn(t, interceptor, nil)

	resp, err := client.Check(bearer(context.Background(), "letmein"), &healthpb.HealthCheckRequest{})
	require.NoError(t, err)
	assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.GetStatus())
}

func TestUnaryAuthorizeDeniesWhenRoleMissing(t *testing.T) {
	t.Parallel()

	adm := security.NewAffirmativeDecisionManager(voter.HasRole("ADMIN"))

	interceptor := chainUnary(
		grpcsec.UnaryServerInterceptor(newEngine("ROLE_USER")), // not ADMIN
		grpcsec.UnaryAuthorize(adm, []security.Attribute{security.Role("ADMIN")}),
	)

	client := dialBufconn(t, interceptor, nil)

	_, err := client.Check(bearer(context.Background(), "letmein"), &healthpb.HealthCheckRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestUnaryAuthorizeDeniesAnonymous(t *testing.T) {
	t.Parallel()

	adm := security.NewAffirmativeDecisionManager(voter.HasRole("ADMIN"))

	// No authentication interceptor in front: the request is anonymous,
	// the role voter denies.
	client := dialBufconn(t,
		grpcsec.UnaryAuthorize(adm, []security.Attribute{security.Role("ADMIN")}),
		nil,
	)

	_, err := client.Check(context.Background(), &healthpb.HealthCheckRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestStreamAuthorizeGrantsAndDenies(t *testing.T) {
	t.Parallel()

	adm := security.NewAffirmativeDecisionManager(voter.HasScope("watch"))

	chain := func(authorities ...string) grpc.StreamServerInterceptor {
		auth := grpcsec.StreamServerInterceptor(newEngine(authorities...))
		authz := grpcsec.StreamAuthorize(adm, []security.Attribute{security.Scope("watch")})

		return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, h grpc.StreamHandler) error {
			return auth(srv, ss, info, func(srv any, ss grpc.ServerStream) error {
				return authz(srv, ss, info, h)
			})
		}
	}

	// Granted: principal carries scope:watch.
	granted := dialBufconn(t, nil, chain("scope:watch"))
	stream, err := granted.Watch(bearer(context.Background(), "letmein"), &healthpb.HealthCheckRequest{})
	require.NoError(t, err)
	resp, err := stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.GetStatus())

	// Denied: principal lacks the scope.
	denied := dialBufconn(t, nil, chain("scope:other"))
	stream, err = denied.Watch(bearer(context.Background(), "letmein"), &healthpb.HealthCheckRequest{})
	require.NoError(t, err)
	_, err = stream.Recv()
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}
