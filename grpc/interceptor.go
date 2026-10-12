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
	"google.golang.org/grpc"
)

const tracerName = "github.com/hyperscale-stack/security/grpc"

// errEngineContract reports a custom [security.Engine] that returned no
// context or no authentication without an error: an internal error.
var errEngineContract = errors.New("grpcsec: the engine returned no context or authentication")

// authenticate runs the engine against the RPC metadata and returns the
// enriched context with the carrier, whose staged writes the caller sends.
// It is shared by the unary and stream interceptors.
func authenticate(ctx context.Context, engine security.Engine, cfg *config, method string) (context.Context, *Carrier, error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "grpcsec.Authenticate")
	defer span.End()

	span.SetAttributes(attribute.String("rpc.method", method))

	carrier := NewCarrier(ctx)

	newCtx, auth, err := engine.Process(ctx, carrier)

	// "no extractor configured" is tolerated only when the caller opted into
	// anonymous fallback; every other error is fatal.
	tolerated := cfg.anonymousFallback && errors.Is(err, security.ErrNoExtractor)

	switch {
	case err != nil && !tolerated:
		return ctx, carrier, fmt.Errorf("grpcsec: authenticate: %w", err)
	case newCtx == nil || auth == nil:
		return ctx, carrier, errEngineContract
	case !auth.IsAuthenticated() && !cfg.anonymousFallback:
		return ctx, carrier, security.ErrAuthenticationRequired
	}

	span.SetAttributes(attribute.Bool("security.authenticated", auth.IsAuthenticated()))

	return newCtx, carrier, nil
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
// It opens a "grpcsec.Authenticate" span but deliberately does NOT open an
// "rpc" span — that belongs to otelgrpc, which users compose alongside
// this interceptor.
func UnaryServerInterceptor(engine security.Engine, opts ...Option) grpc.UnaryServerInterceptor {
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
// as the stream's header.
func StreamServerInterceptor(engine security.Engine, opts ...Option) grpc.StreamServerInterceptor {
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

// wrappedStream overrides Context() so downstream handlers see the
// authenticated context. Every other method delegates to the embedded
// grpc.ServerStream.
type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the security-enriched context.
func (w *wrappedStream) Context() context.Context { return w.ctx }
