// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grpcsec_test

import (
	"context"
	"testing"

	"github.com/hyperscale-stack/security"
	grpcsec "github.com/hyperscale-stack/security/grpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	otelcodes "go.opentelemetry.io/otel/codes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// secret is a panic value that must reach neither the client nor a trace.
const secret = "SECRET-token-in-a-panic"

// panickingAuthenticator panics on the token "boom", as an application
// authenticator dereferencing a typed-nil user does, and accepts
// "letmein".
type panickingAuthenticator struct{ tokenAuthenticator }

func (a panickingAuthenticator) Authenticate(ctx context.Context, in security.Authentication) (security.Authentication, error) {
	if p, ok := in.(pendingAuth); ok && p.token == "boom" {
		panic(secret)
	}

	return a.tokenAuthenticator.Authenticate(ctx, in)
}

// panickingADM panics on every decision.
type panickingADM struct{}

func (panickingADM) Decide(context.Context, security.Authentication, []security.Attribute) error {
	panic(secret)
}

// Audit I-26: grpc-go recovers no panic, and neither did grpcsec — one
// panic in an extractor, authenticator or voter ended the process. The
// security pipeline's panics are answered Internal, and the server goes on.
func TestInterceptorsContainPanicsOfTheSecurityPipeline(t *testing.T) {
	t.Parallel()

	engine := security.NewEngine(security.NewManager(panickingAuthenticator{}), tokenExtractor{})
	client := dialWithOptions(t, grpcsec.ServerOptions(engine)...)

	for range 2 {
		_, err := client.Check(bearer(context.Background(), "boom"), &healthpb.HealthCheckRequest{})
		st := status.Convert(err)
		assert.Equal(t, codes.Internal, st.Code())
		assert.Equal(t, "internal error", st.Message())

		stream, err := client.Watch(bearer(context.Background(), "boom"), &healthpb.HealthCheckRequest{})
		if err == nil {
			_, err = stream.Recv()
		}

		assert.Equal(t, codes.Internal, status.Code(err))
		assert.NotContains(t, status.Convert(err).Message(), secret)
	}

	resp, err := client.Check(bearer(context.Background(), "letmein"), &healthpb.HealthCheckRequest{})
	require.NoError(t, err, "the server survived")
	assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.GetStatus())
}

func TestAuthorizationContainsPanicsOfTheDecisionManager(t *testing.T) {
	t.Parallel()

	engine := security.NewEngine(security.NewManager(tokenAuthenticator{}), tokenExtractor{})
	client := dialWithOptions(t, append(grpcsec.ServerOptions(engine),
		grpcsec.AuthorizeServerOptions(panickingADM{}, []security.Attribute{security.Role("ADMIN")})...)...)

	_, err := client.Check(bearer(context.Background(), "letmein"), &healthpb.HealthCheckRequest{})
	assert.Equal(t, codes.Internal, status.Code(err))

	stream, err := client.Watch(bearer(context.Background(), "letmein"), &healthpb.HealthCheckRequest{})
	if err == nil {
		_, err = stream.Recv()
	}

	assert.Equal(t, codes.Internal, status.Code(err))

	_, err = client.Check(bearer(context.Background(), "letmein"), &healthpb.HealthCheckRequest{})
	assert.Equal(t, codes.Internal, status.Code(err), "the server survived")
}

// A recovered panic leaves a trace — the span's error status and a
// "panic recovered" event — but never its value, which may hold a
// credential.
func TestRecoveredPanicsLeaveATraceWithoutTheirValue(t *testing.T) { //nolint:paralleltest // installs the process-wide tracer provider
	engine := security.NewEngine(security.NewManager(panickingAuthenticator{}), tokenExtractor{})
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer boom"))

	spans := recordSpans(func() {
		_, err := grpcsec.UnaryServerInterceptor(engine)(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/x/Y"},
			func(context.Context, any) (any, error) { return nil, nil })
		require.Error(t, err)

		_, err = grpcsec.UnaryAuthorize(panickingADM{}, []security.Attribute{security.Role("ADMIN")})(context.Background(), nil,
			&grpc.UnaryServerInfo{FullMethod: "/x/Y"}, func(context.Context, any) (any, error) { return nil, nil })
		require.Error(t, err)
	})

	for _, name := range []string{"grpcsec.Authenticate", "grpcsec.Authorize"} {
		var found *recordedSpan

		for _, s := range spans {
			if s.name == name {
				found = s
			}
		}

		require.NotNil(t, found, name)
		assert.Equal(t, otelcodes.Error, found.status, name)
		assert.Contains(t, found.events, "panic recovered", name)

		for _, s := range spans {
			assert.NotContains(t, s.evidence(), secret, s.name)
		}
	}
}
