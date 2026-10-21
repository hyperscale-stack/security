// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grpcsec

import (
	"context"
	"errors"
	"fmt"

	"github.com/hyperscale-stack/security"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
)

const tracerName = "github.com/hyperscale-stack/security/grpc"

// errEngineContract reports a custom [security.Engine] that returned no
// context or no authentication (nil or a typed nil) without an error: an
// internal error.
var errEngineContract = errors.New("grpcsec: the engine returned no context or authentication")

// errPipelinePanic reports a panic of the security pipeline — an
// extractor, an authenticator, a voter —, recovered: an internal error.
// It never carries the panic value, which may hold a credential.
var errPipelinePanic = errors.New("grpcsec: panic in the security pipeline")

// contain runs fn and turns a panic into errPipelinePanic: grpc-go recovers
// no panic, so one would end the process. The span records the error status
// and a "panic recovered" event, never the panic value.
func contain(span trace.Span, fn func() error) (err error) {
	defer func() {
		if recover() != nil {
			span.AddEvent("panic recovered")
			span.SetStatus(otelcodes.Error, security.ErrorClassOther)

			err = errPipelinePanic
		}
	}()

	return fn()
}

// authenticate runs the engine against the RPC metadata and returns the
// enriched context with the carrier, whose staged writes the caller sends.
// It is shared by the unary and stream interceptors.
func authenticate(ctx context.Context, engine security.Engine, cfg *config, method string) (context.Context, *Carrier, error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "grpcsec.Authenticate")
	defer span.End()

	span.SetAttributes(attribute.String("rpc.method", method))

	ctx = withClientAddr(ctx)
	carrier := NewCarrier(ctx)

	var (
		newCtx context.Context
		auth   security.Authentication
	)

	err := contain(span, func() (err error) {
		newCtx, auth, err = engine.Process(ctx, carrier)

		return err //nolint:wrapcheck // wrapped below
	})

	// "no extractor configured" is tolerated only when the caller opted into
	// anonymous fallback; every other error is fatal.
	tolerated := cfg.anonymousFallback && errors.Is(err, security.ErrNoExtractor)

	switch {
	case err != nil && !tolerated:
		return ctx, carrier, fmt.Errorf("grpcsec: authenticate: %w", err)
	case newCtx == nil || isNil(auth):
		return ctx, carrier, errEngineContract
	case !auth.IsAuthenticated() && !cfg.anonymousFallback:
		return ctx, carrier, security.ErrAuthenticationRequired
	}

	span.SetAttributes(attribute.Bool("security.authenticated", auth.IsAuthenticated()))

	return newCtx, carrier, nil
}

// withClientAddr stores the RPC's peer address in ctx as the client
// address an [security.AttemptLimiter] keys on, unless an interceptor
// before stored one with [security.WithClientAddr] or the peer has no IP
// address (a Unix socket).
func withClientAddr(ctx context.Context) context.Context {
	if _, ok := security.ClientAddrFromContext(ctx); ok {
		return ctx
	}

	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return ctx
	}

	addr := security.ParseClientAddr(p.Addr.String())
	if !addr.IsValid() {
		return ctx
	}

	return security.WithClientAddr(ctx, addr)
}

// UnaryServerInterceptor authenticates every unary RPC. On success the
// handler runs with the request context enriched via
// [security.WithAuthentication]; on failure the configured [ErrorMapper]
// turns the security error into a gRPC status error and the handler is
// not invoked. The metadata the extractors stage on the [Carrier] is sent
// as the response header, refused calls included.
//
// Install [StreamServerInterceptor] too — or use [ServerOptions]: this
// interceptor leaves streaming RPCs unauthenticated.
//
// The interceptor stores the RPC's peer address as the client address an
// [security.AttemptLimiter] keys on, unless an interceptor before it stored
// one with [security.WithClientAddr] — do so behind a proxy (Envoy, a load
// balancer terminating the connection), or every RPC counts as the proxy's.
//
// A panic of the security pipeline — an extractor, an authenticator — is
// recovered and answered as an internal error (codes.Internal with the
// default mapper): grpc-go recovers no panic, and one unauthenticated RPC
// would otherwise end the process. The handler's own panics are not
// recovered.
//
// It opens a "grpcsec.Authenticate" span but deliberately does NOT open an
// "rpc" span — that belongs to otelgrpc, which users compose alongside
// this interceptor. It panics if engine is nil.
func UnaryServerInterceptor(engine security.Engine, opts ...Option) grpc.UnaryServerInterceptor {
	mustEngine(engine)

	cfg := buildConfig(opts...)
	mapper := cfg.ownMapper()

	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		newCtx, carrier, err := authenticate(ctx, engine, cfg, info.FullMethod)

		if md := carrier.ResponseMetadata(); md.Len() > 0 {
			// Sent with the response, or before the status of a refused
			// call. SetHeader only fails outside a gRPC server.
			_ = grpc.SetHeader(ctx, md)
		}

		if err != nil {
			return nil, mapper.Map(ctx, err)
		}

		return handler(withErrorMapper(newCtx, mapper), req)
	}
}

// StreamServerInterceptor is the streaming counterpart of
// [UnaryServerInterceptor]. The wrapped stream exposes the enriched
// context through ServerStream.Context(), and the staged metadata is sent
// as the stream's header. It panics if engine is nil.
func StreamServerInterceptor(engine security.Engine, opts ...Option) grpc.StreamServerInterceptor {
	mustEngine(engine)

	cfg := buildConfig(opts...)
	mapper := cfg.ownMapper()

	return func(
		srv any,
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		newCtx, carrier, err := authenticate(ss.Context(), engine, cfg, info.FullMethod)

		if md := carrier.ResponseMetadata(); md.Len() > 0 {
			// Sent before the first message, or before the status of a
			// refused stream.
			_ = ss.SetHeader(md)
		}

		if err != nil {
			return mapper.Map(ss.Context(), err)
		}

		return handler(srv, &wrappedStream{ServerStream: ss, ctx: withErrorMapper(newCtx, mapper)})
	}
}

// mustEngine refuses a nil engine at construction: grpc-go recovers no
// panic, so it would otherwise crash the server on the first RPC.
func mustEngine(engine security.Engine) {
	if isNil(engine) {
		panic("grpcsec: nil Engine")
	}
}

// wrappedStream overrides Context() so downstream handlers see the
// authenticated context. Every other method delegates to the embedded
// grpc.ServerStream.
type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the security-enriched context.
func (w *wrappedStream) Context() context.Context { return w.ctx }
