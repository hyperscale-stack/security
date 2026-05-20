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
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func newEngine(authorities ...string) security.Engine {
	return security.NewEngine(
		security.NewManager(tokenAuthenticator{authorities: authorities}),
		tokenExtractor{},
	)
}

func bearer(ctx context.Context, token string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
}

func TestUnaryInterceptorAllowsAuthenticatedCall(t *testing.T) {
	t.Parallel()

	client := dialBufconn(t, grpcsec.UnaryServerInterceptor(newEngine()), nil)

	resp, err := client.Check(bearer(context.Background(), "letmein"), &healthpb.HealthCheckRequest{})
	require.NoError(t, err)
	assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.GetStatus())
}

func TestUnaryInterceptorRejectsMissingCredential(t *testing.T) {
	t.Parallel()

	client := dialBufconn(t, grpcsec.UnaryServerInterceptor(newEngine()), nil)

	_, err := client.Check(context.Background(), &healthpb.HealthCheckRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestUnaryInterceptorRejectsBadToken(t *testing.T) {
	t.Parallel()

	client := dialBufconn(t, grpcsec.UnaryServerInterceptor(newEngine()), nil)

	_, err := client.Check(bearer(context.Background(), "wrong"), &healthpb.HealthCheckRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestUnaryInterceptorAnonymousFallbackLetsCallThrough(t *testing.T) {
	t.Parallel()

	client := dialBufconn(t,
		grpcsec.UnaryServerInterceptor(newEngine(), grpcsec.WithAnonymousFallback(true)),
		nil,
	)

	// No credential, but the fallback lets the unary RPC reach the handler.
	resp, err := client.Check(context.Background(), &healthpb.HealthCheckRequest{})
	require.NoError(t, err)
	assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.GetStatus())
}

func TestStreamInterceptorAllowsAuthenticatedStream(t *testing.T) {
	t.Parallel()

	client := dialBufconn(t, nil, grpcsec.StreamServerInterceptor(newEngine()))

	stream, err := client.Watch(bearer(context.Background(), "letmein"), &healthpb.HealthCheckRequest{})
	require.NoError(t, err)

	// The health Watch server pushes at least one status update.
	resp, err := stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.GetStatus())
}

func TestStreamInterceptorRejectsMissingCredential(t *testing.T) {
	t.Parallel()

	client := dialBufconn(t, nil, grpcsec.StreamServerInterceptor(newEngine()))

	stream, err := client.Watch(context.Background(), &healthpb.HealthCheckRequest{})
	require.NoError(t, err, "stream opens lazily; the error surfaces on Recv")

	_, err = stream.Recv()
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestInterceptorCustomErrorMapper(t *testing.T) {
	t.Parallel()

	mapper := &recordingMapper{ErrorMapper: grpcsec.DefaultErrorMapper()}
	client := dialBufconn(t,
		grpcsec.UnaryServerInterceptor(newEngine(), grpcsec.WithErrorMapper(mapper)),
		nil,
	)

	_, err := client.Check(context.Background(), &healthpb.HealthCheckRequest{})
	require.Error(t, err)
	assert.True(t, mapper.called.Load())
}

type recordingMapper struct {
	grpcsec.ErrorMapper
	called atomicBool
}

func (m *recordingMapper) Map(ctx context.Context, err error) error {
	m.called.Store(true)

	return m.ErrorMapper.Map(ctx, err)
}

type atomicBool struct {
	mu sync.Mutex
	v  bool
}

func (a *atomicBool) Store(b bool) { a.mu.Lock(); a.v = b; a.mu.Unlock() }
func (a *atomicBool) Load() bool   { a.mu.Lock(); defer a.mu.Unlock(); return a.v }

func TestUnaryInterceptorIsRaceSafe(t *testing.T) {
	t.Parallel()

	client := dialBufconn(t, grpcsec.UnaryServerInterceptor(newEngine()), nil)

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			_, err := client.Check(bearer(context.Background(), "letmein"), &healthpb.HealthCheckRequest{})
			assert.NoError(t, err)
		}()
	}

	wg.Wait()
}
