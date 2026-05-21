// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package connectrpcsec

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"connectrpc.com/connect"
	"github.com/hyperscale-stack/security"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

const tracerName = "github.com/hyperscale-stack/security/connectrpc"

// flushHeader copies the staged carrier writes into dst, a live response
// header. In the common case the engine writes nothing and this is a no-op.
func flushHeader(dst, staged http.Header) {
	for key, values := range staged {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

// authenticate runs the engine against the RPC request header and returns the
// enriched context together with the Carrier (so the caller can flush staged
// response headers). It is shared by the unary and streaming handlers.
func authenticate(
	ctx context.Context,
	engine security.Engine,
	cfg *config,
	procedure string,
	header http.Header,
) (context.Context, *Carrier, error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "connectrpcsec.Authenticate")
	defer span.End()

	span.SetAttributes(attribute.String("rpc.method", procedure))

	carrier := NewCarrier(header)

	newCtx, auth, err := engine.Process(ctx, carrier)
	if err != nil {
		// "no extractor configured" is tolerated only when the caller
		// opted into anonymous fallback; every other error is fatal.
		tolerated := cfg.anonymousFallback && errors.Is(err, security.ErrNoExtractor)
		if !tolerated {
			return ctx, carrier, fmt.Errorf("connectrpcsec: authenticate: %w", err)
		}
	}

	if !auth.IsAuthenticated() && !cfg.anonymousFallback {
		return ctx, carrier, security.ErrInvalidCredentials
	}

	span.SetAttributes(attribute.Bool("security.authenticated", auth.IsAuthenticated()))

	return newCtx, carrier, nil
}

// AuthenticationInterceptor is a [connect.Interceptor] that authenticates
// every inbound RPC against a [security.Engine]. On success the handler runs
// with the request context enriched via [security.WithAuthentication]; on
// failure the configured [ErrorMapper] turns the security error into a
// Connect error and the handler is not invoked.
//
// It opens a "connectrpcsec.Authenticate" span but deliberately does NOT open
// an "rpc" span — that belongs to otelconnect, which users compose alongside
// this interceptor.
type AuthenticationInterceptor struct {
	engine security.Engine
	cfg    *config
}

// NewAuthenticationInterceptor builds a [connect.Interceptor] that
// authenticates every inbound unary and streaming RPC against engine. Install
// it with connect.WithInterceptors(...). Client-side calls are passed through
// untouched.
func NewAuthenticationInterceptor(engine security.Engine, opts ...Option) *AuthenticationInterceptor {
	return &AuthenticationInterceptor{engine: engine, cfg: buildConfig(opts...)}
}

// Compile-time check.
var _ connect.Interceptor = (*AuthenticationInterceptor)(nil)

// WrapUnary implements [connect.Interceptor]. Outbound client calls are passed
// through untouched; inbound handler calls are authenticated.
func (i *AuthenticationInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if req.Spec().IsClient {
			return next(ctx, req) //nolint:wrapcheck // pass-through: the client error is the terminal value
		}

		newCtx, carrier, err := authenticate(ctx, i.engine, i.cfg, req.Spec().Procedure, req.Header())
		if err != nil {
			return nil, i.cfg.errorMapper.Map(ctx, err)
		}

		resp, err := next(newCtx, req)
		if resp != nil {
			flushHeader(resp.Header(), carrier.ResponseHeader())
		}

		return resp, err //nolint:wrapcheck // the handler / connect error is the terminal wire value
	}
}

// WrapStreamingHandler implements [connect.Interceptor]. It authenticates the
// stream before the handler runs and exposes the enriched context through the
// handler's context argument.
func (i *AuthenticationInterceptor) WrapStreamingHandler(
	next connect.StreamingHandlerFunc,
) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		newCtx, carrier, err := authenticate(ctx, i.engine, i.cfg, conn.Spec().Procedure, conn.RequestHeader())
		if err != nil {
			return i.cfg.errorMapper.Map(ctx, err)
		}

		flushHeader(conn.ResponseHeader(), carrier.ResponseHeader())

		return next(newCtx, conn) //nolint:wrapcheck // the handler error is the terminal wire value
	}
}

// WrapStreamingClient implements [connect.Interceptor] as a pass-through.
// [connect.StreamingClientFunc] exposes only a [connect.Spec] and returns no
// error, so the security engine — which is server-side — cannot run here.
func (i *AuthenticationInterceptor) WrapStreamingClient(
	next connect.StreamingClientFunc,
) connect.StreamingClientFunc {
	return next
}
