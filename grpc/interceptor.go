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

// authenticate runs the engine against the RPC metadata and returns the
// enriched context. It is shared by the unary and stream interceptors.
func authenticate(ctx context.Context, engine security.Engine, cfg *config, method string) (context.Context, error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "grpcsec.Authenticate")
	defer span.End()

	span.SetAttributes(attribute.String("rpc.method", method))

	carrier := NewCarrier(ctx)

	newCtx, auth, err := engine.Process(ctx, carrier)
	if err != nil {
		// "no extractor configured" is tolerated only when the caller
		// opted into anonymous fallback; every other error is fatal.
		tolerated := cfg.anonymousFallback && errors.Is(err, security.ErrNoExtractor)
		if !tolerated {
			return ctx, fmt.Errorf("grpcsec: authenticate: %w", err)
		}
	}

	if !auth.IsAuthenticated() && !cfg.anonymousFallback {
		return ctx, security.ErrInvalidCredentials
	}

	span.SetAttributes(attribute.Bool("security.authenticated", auth.IsAuthenticated()))

	return newCtx, nil
}

// UnaryServerInterceptor authenticates every unary RPC. On success the
// handler runs with the request context enriched via
// [security.WithAuthentication]; on failure the configured [ErrorMapper]
// turns the security error into a gRPC status error and the handler is
// not invoked.
//
// It opens a "grpcsec.Authenticate" span but deliberately does NOT open an
// "rpc" span — that belongs to otelgrpc, which users compose alongside
// this interceptor.
func UnaryServerInterceptor(engine security.Engine, opts ...Option) grpc.UnaryServerInterceptor {
	cfg := buildConfig(opts...)

	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		newCtx, err := authenticate(ctx, engine, cfg, info.FullMethod)
		if err != nil {
			return nil, cfg.errorMapper.Map(ctx, err)
		}

		return handler(newCtx, req)
	}
}

// StreamServerInterceptor is the streaming counterpart of
// [UnaryServerInterceptor]. The wrapped stream exposes the enriched
// context through ServerStream.Context().
func StreamServerInterceptor(engine security.Engine, opts ...Option) grpc.StreamServerInterceptor {
	cfg := buildConfig(opts...)

	return func(
		srv any,
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		newCtx, err := authenticate(ss.Context(), engine, cfg, info.FullMethod)
		if err != nil {
			return cfg.errorMapper.Map(ss.Context(), err)
		}

		return handler(srv, &wrappedStream{ServerStream: ss, ctx: newCtx})
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
