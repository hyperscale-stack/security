// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grpcsec_test

import (
	"context"
	"sync"
	"testing"

	"github.com/hyperscale-stack/security"
	grpcsec "github.com/hyperscale-stack/security/grpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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
		assert.Contains(t, found.attrs, "error.type=_OTHER", name, "review minor 2: the core's error.type convention")

		for _, s := range spans {
			assert.NotContains(t, s.evidence(), secret, s.name)
		}
	}
}

// grantAll grants every decision.
type grantAll struct{}

func (grantAll) Supports(security.Attribute) bool { return true }
func (grantAll) Vote(context.Context, security.Authentication, []security.Attribute) security.Decision {
	return security.DecisionGrant
}

// Review minor 1: only the security pipeline is contained — the handler's
// own panics are the application's, and propagate to its recovery
// interceptor (or crash the server, as grpc-go does by default).
func TestHandlerPanicsAreNotRecovered(t *testing.T) {
	t.Parallel()

	engine := security.NewEngine(security.NewManager(tokenAuthenticator{}), tokenExtractor{})
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer letmein"))
	info := &grpc.UnaryServerInfo{FullMethod: "/x/Y"}
	streamInfo := &grpc.StreamServerInfo{FullMethod: "/x/Y"}
	panicking := func(context.Context, any) (any, error) { panic("handler") }
	panickingStream := func(any, grpc.ServerStream) error { panic("stream handler") }

	authed, _, err := engine.Process(ctx, grpcsec.NewCarrier(ctx))
	require.NoError(t, err)

	adm := security.NewAffirmativeDecisionManager(grantAll{})
	attrs := []security.Attribute{security.Role("ADMIN")}

	assert.PanicsWithValue(t, "handler", func() {
		_, _ = grpcsec.UnaryServerInterceptor(engine)(ctx, nil, info, panicking)
	})
	assert.PanicsWithValue(t, "stream handler", func() {
		_ = grpcsec.StreamServerInterceptor(engine)(nil, peerStream{ctx: ctx}, streamInfo, panickingStream)
	})
	assert.PanicsWithValue(t, "handler", func() {
		_, _ = grpcsec.UnaryAuthorize(adm, attrs)(authed, nil, info, panicking)
	})
	assert.PanicsWithValue(t, "stream handler", func() {
		_ = grpcsec.StreamAuthorize(adm, attrs)(nil, peerStream{ctx: authed}, streamInfo, panickingStream)
	})
}

// Review minor 1: the error a custom ErrorMapper receives for a recovered
// panic never carries the panic value — a mapper may log its error.
func TestErrorMappersNeverSeeThePanicValue(t *testing.T) {
	t.Parallel()

	var seen []error

	mapper := grpcsec.NewMockErrorMapper(t)
	mapper.EXPECT().Map(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, err error) error {
		seen = append(seen, err)

		return status.Error(codes.Internal, "x")
	}).Times(2)

	engine := security.NewEngine(security.NewManager(panickingAuthenticator{}), tokenExtractor{})
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer boom"))
	info := &grpc.UnaryServerInfo{FullMethod: "/x/Y"}

	_, err := grpcsec.UnaryServerInterceptor(engine, grpcsec.WithErrorMapper(mapper))(ctx, nil, info,
		func(context.Context, any) (any, error) { return nil, nil })
	require.Error(t, err)

	_, err = grpcsec.UnaryAuthorize(panickingADM{}, nil, grpcsec.WithErrorMapper(mapper))(context.Background(), nil, info,
		func(context.Context, any) (any, error) { return nil, nil })
	require.Error(t, err)

	require.Len(t, seen, 2)

	for _, err := range seen {
		assert.NotContains(t, err.Error(), secret)
		assert.Equal(t, security.ErrorClassOther, security.ErrorClass(err), "an internal error")
	}
}

// Axel's decision UD-1: WithPanicHandler receives the recovered value —
// under the application's responsibility, since it may hold a credential —
// so that a panic of the security pipeline stays visible: an outer recovery
// interceptor no longer sees it.
func TestWithPanicHandlerReceivesTheRecoveredValue(t *testing.T) {
	t.Parallel()

	var (
		mu        sync.Mutex
		recovered []any
	)

	handler := grpcsec.WithPanicHandler(func(ctx context.Context, v any) {
		mu.Lock()
		defer mu.Unlock()

		assert.NotNil(t, ctx)
		recovered = append(recovered, v)
	})

	engine := security.NewEngine(security.NewManager(panickingAuthenticator{}), tokenExtractor{})
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer boom"))
	info := &grpc.UnaryServerInfo{FullMethod: "/x/Y"}
	ok := func(context.Context, any) (any, error) { return nil, nil }

	_, err := grpcsec.UnaryServerInterceptor(engine, handler)(ctx, nil, info, ok)
	assert.Equal(t, codes.Internal, status.Code(err))

	err = grpcsec.StreamServerInterceptor(engine, handler)(nil, peerStream{ctx: ctx}, &grpc.StreamServerInfo{FullMethod: "/x/Y"},
		func(any, grpc.ServerStream) error { return nil })
	assert.Equal(t, codes.Internal, status.Code(err))

	_, err = grpcsec.UnaryAuthorize(panickingADM{}, nil, handler)(context.Background(), nil, info, ok)
	assert.Equal(t, codes.Internal, status.Code(err))

	err = grpcsec.StreamAuthorize(panickingADM{}, nil, handler)(nil, peerStream{ctx: context.Background()},
		&grpc.StreamServerInfo{FullMethod: "/x/Y"}, func(any, grpc.ServerStream) error { return nil })
	assert.Equal(t, codes.Internal, status.Code(err))

	assert.Equal(t, []any{secret, secret, secret, secret}, recovered)

	// A panicking handler is itself contained: the server goes on.
	bad := grpcsec.WithPanicHandler(func(context.Context, any) { panic("handler of the handler") })

	assert.NotPanics(t, func() {
		_, err = grpcsec.UnaryServerInterceptor(engine, bad)(ctx, nil, info, ok)
	})
	assert.Equal(t, codes.Internal, status.Code(err))

	// WithPanicHandler(nil) keeps no handler.
	assert.NotPanics(t, func() {
		_, err = grpcsec.UnaryServerInterceptor(engine, grpcsec.WithPanicHandler(nil))(ctx, nil, info, ok)
	})
	assert.Equal(t, codes.Internal, status.Code(err))
}
