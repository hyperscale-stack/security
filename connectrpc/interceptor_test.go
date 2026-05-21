// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package connectrpcsec_test

import (
	"context"
	"sync"
	"testing"

	"connectrpc.com/connect"
	"github.com/hyperscale-stack/security"
	connectrpcsec "github.com/hyperscale-stack/security/connectrpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// unaryReq builds a server-side unary request carrying the Bearer token, or
// no Authorization header when token is empty.
func unaryReq(token string) connect.AnyRequest {
	req := connect.NewRequest(&struct{}{})
	if token != "" {
		req.Header().Set("Authorization", "Bearer "+token)
	}

	return req
}

// recordingUnary is a connect.UnaryFunc spy: it records its invocation and the
// authentication carried by the context it received.
type recordingUnary struct {
	called bool
	auth   security.Authentication
}

func (s *recordingUnary) fn(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
	s.called = true
	s.auth, _ = security.FromContext(ctx)

	return connect.NewResponse(&struct{}{}), nil
}

// recordingStream is a connect.StreamingHandlerFunc spy.
type recordingStream struct {
	called bool
	auth   security.Authentication
}

func (s *recordingStream) fn(ctx context.Context, _ connect.StreamingHandlerConn) error {
	s.called = true
	s.auth, _ = security.FromContext(ctx)

	return nil
}

func TestWrapUnaryAllowsAuthenticatedCall(t *testing.T) {
	t.Parallel()

	spy := &recordingUnary{}
	wrapped := connectrpcsec.NewAuthenticationInterceptor(newEngine()).WrapUnary(spy.fn)

	resp, err := wrapped(context.Background(), unaryReq("letmein"))
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, spy.called)
	assert.True(t, spy.auth.IsAuthenticated())
	assert.Equal(t, "alice", spy.auth.Name())
}

func TestWrapUnaryRejectsMissingCredential(t *testing.T) {
	t.Parallel()

	spy := &recordingUnary{}
	wrapped := connectrpcsec.NewAuthenticationInterceptor(newEngine()).WrapUnary(spy.fn)

	_, err := wrapped(context.Background(), unaryReq(""))
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	assert.False(t, spy.called)
}

func TestWrapUnaryRejectsBadToken(t *testing.T) {
	t.Parallel()

	spy := &recordingUnary{}
	wrapped := connectrpcsec.NewAuthenticationInterceptor(newEngine()).WrapUnary(spy.fn)

	_, err := wrapped(context.Background(), unaryReq("wrong"))
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	assert.False(t, spy.called)
}

func TestWrapUnaryAnonymousFallbackLetsCallThrough(t *testing.T) {
	t.Parallel()

	spy := &recordingUnary{}
	wrapped := connectrpcsec.NewAuthenticationInterceptor(
		newEngine(),
		connectrpcsec.WithAnonymousFallback(true),
	).WrapUnary(spy.fn)

	resp, err := wrapped(context.Background(), unaryReq(""))
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, spy.called)
	assert.False(t, spy.auth.IsAuthenticated())
}

func TestWrapUnarySkipsClientCall(t *testing.T) {
	t.Parallel()

	spy := &recordingUnary{}
	wrapped := connectrpcsec.NewAuthenticationInterceptor(newEngine()).WrapUnary(spy.fn)

	// A client-side call carries no credential yet still reaches next.
	_, err := wrapped(context.Background(), clientRequest{connect.NewRequest(&struct{}{})})
	require.NoError(t, err)
	assert.True(t, spy.called)
}

func TestWrapUnaryFlushesResponseHeader(t *testing.T) {
	t.Parallel()

	engine := security.NewEngine(
		security.NewManager(tokenAuthenticator{}),
		writingExtractor{},
	)

	var got connect.AnyResponse

	next := func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		_ = ctx
		got = connect.NewResponse(&struct{}{})

		return got, nil
	}

	wrapped := connectrpcsec.NewAuthenticationInterceptor(engine).WrapUnary(next)

	_, err := wrapped(context.Background(), unaryReq("letmein"))
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "applied", got.Header().Get("X-Authn-Trace"))
}

func TestWrapStreamingHandlerAllowsAuthenticatedStream(t *testing.T) {
	t.Parallel()

	spy := &recordingStream{}
	wrapped := connectrpcsec.NewAuthenticationInterceptor(newEngine()).WrapStreamingHandler(spy.fn)

	err := wrapped(context.Background(), newStreamConn(bearerHeader("letmein")))
	require.NoError(t, err)
	assert.True(t, spy.called)
	assert.True(t, spy.auth.IsAuthenticated())
}

func TestWrapStreamingHandlerRejectsMissingCredential(t *testing.T) {
	t.Parallel()

	spy := &recordingStream{}
	wrapped := connectrpcsec.NewAuthenticationInterceptor(newEngine()).WrapStreamingHandler(spy.fn)

	err := wrapped(context.Background(), newStreamConn(nil))
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	assert.False(t, spy.called)
}

func TestWrapStreamingHandlerAnonymousFallback(t *testing.T) {
	t.Parallel()

	spy := &recordingStream{}
	wrapped := connectrpcsec.NewAuthenticationInterceptor(
		newEngine(),
		connectrpcsec.WithAnonymousFallback(true),
	).WrapStreamingHandler(spy.fn)

	err := wrapped(context.Background(), newStreamConn(nil))
	require.NoError(t, err)
	assert.True(t, spy.called)
	assert.False(t, spy.auth.IsAuthenticated())
}

func TestWrapStreamingHandlerFlushesResponseHeader(t *testing.T) {
	t.Parallel()

	engine := security.NewEngine(
		security.NewManager(tokenAuthenticator{}),
		writingExtractor{},
	)

	spy := &recordingStream{}
	conn := newStreamConn(bearerHeader("letmein"))
	wrapped := connectrpcsec.NewAuthenticationInterceptor(engine).WrapStreamingHandler(spy.fn)

	err := wrapped(context.Background(), conn)
	require.NoError(t, err)
	assert.Equal(t, "applied", conn.ResponseHeader().Get("X-Authn-Trace"))
}

func TestWrapStreamingClientIsPassThrough(t *testing.T) {
	t.Parallel()

	called := false

	next := func(_ context.Context, _ connect.Spec) connect.StreamingClientConn {
		called = true

		return nil
	}

	wrapped := connectrpcsec.NewAuthenticationInterceptor(newEngine()).WrapStreamingClient(next)
	_ = wrapped(context.Background(), connect.Spec{})

	assert.True(t, called)
}

func TestInterceptorCustomErrorMapper(t *testing.T) {
	t.Parallel()

	mapper := &recordingMapper{ErrorMapper: connectrpcsec.DefaultErrorMapper()}
	spy := &recordingUnary{}
	wrapped := connectrpcsec.NewAuthenticationInterceptor(
		newEngine(),
		connectrpcsec.WithErrorMapper(mapper),
	).WrapUnary(spy.fn)

	_, err := wrapped(context.Background(), unaryReq(""))
	require.Error(t, err)
	assert.True(t, mapper.called.Load())
}

// WithErrorMapper(nil) keeps the default mapper.
func TestWithErrorMapperNilKeepsDefault(t *testing.T) {
	t.Parallel()

	spy := &recordingUnary{}
	wrapped := connectrpcsec.NewAuthenticationInterceptor(
		newEngine(),
		connectrpcsec.WithErrorMapper(nil),
	).WrapUnary(spy.fn)

	_, err := wrapped(context.Background(), unaryReq(""))
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

func TestWrapUnaryIsRaceSafe(t *testing.T) {
	t.Parallel()

	interceptor := connectrpcsec.NewAuthenticationInterceptor(newEngine())

	var wg sync.WaitGroup

	for range 50 {
		wg.Go(func() {
			spy := &recordingUnary{}
			wrapped := interceptor.WrapUnary(spy.fn)

			_, err := wrapped(context.Background(), unaryReq("letmein"))
			assert.NoError(t, err)
		})
	}

	wg.Wait()
}

type recordingMapper struct {
	connectrpcsec.ErrorMapper
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

// writingExtractor reads the Bearer token like tokenExtractor but also stages
// a response header on the carrier, exercising the interceptor's header flush.
type writingExtractor struct{}

func (writingExtractor) Extract(
	_ context.Context,
	c security.Carrier,
) (security.Authentication, error) {
	v := c.Get("authorization")
	if v == "" {
		return nil, nil
	}

	c.Set("X-Authn-Trace", "applied")

	const prefix = "Bearer "
	if len(v) <= len(prefix) {
		return nil, nil
	}

	return pendingAuth{token: v[len(prefix):]}, nil
}
