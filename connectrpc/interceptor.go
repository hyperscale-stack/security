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

// errEngineContract reports a custom [security.Engine] that returned no
// context or no authentication without an error: an internal error.
var errEngineContract = errors.New("connectrpcsec: the engine returned no context or authentication")

// flushHeader copies the staged carrier writes into dst, a live response
// header or an error's metadata. In the common case the engine writes
// nothing and this is a no-op.
func flushHeader(dst, staged http.Header) {
	for key, values := range staged {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

// withStaged merges the staged carrier writes into the metadata of a
// Connect error — the response headers of a refused unary call.
func withStaged(err error, carrier *Carrier) error {
	var ce *connect.Error
	if errors.As(err, &ce) {
		flushHeader(ce.Meta(), carrier.ResponseHeader())
	}

	return err
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

	// "no extractor configured" is tolerated only when the caller opted into
	// anonymous fallback; every other error is fatal.
	tolerated := cfg.anonymousFallback && errors.Is(err, security.ErrNoExtractor)

	switch {
	case err != nil && !tolerated:
		return ctx, carrier, fmt.Errorf("connectrpcsec: authenticate: %w", err)
	case newCtx == nil || auth == nil:
		return ctx, carrier, errEngineContract
	case !auth.IsAuthenticated() && !cfg.anonymousFallback:
		return ctx, carrier, security.ErrAuthenticationRequired
	}

	span.SetAttributes(attribute.Bool("security.authenticated", auth.IsAuthenticated()))

	return newCtx, carrier, nil
}

// AuthenticationInterceptor is a [connect.Interceptor] that authenticates
// every inbound RPC against a [security.Engine]. On success the handler runs
// with the request context enriched via [security.WithAuthentication]; on
// failure the configured [ErrorMapper] turns the security error into a
// Connect error — with its WWW-Authenticate challenge — and the handler is
// not invoked. The headers the extractors stage on the [Carrier] reach the
// client on every path: the response, a refusal or a handler error.
//
// It opens a "connectrpcsec.Authenticate" span but deliberately does NOT open
// an "rpc" span — that belongs to otelconnect, which users compose alongside
// this interceptor.
type AuthenticationInterceptor struct {
	engine security.Engine
	cfg    *config
	mapper ErrorMapper
}

// NewAuthenticationInterceptor builds a [connect.Interceptor] that
// authenticates every inbound unary and streaming RPC against engine. Install
// it with connect.WithInterceptors(...). Client-side calls are passed through
// untouched. It panics on an invalid challenge configuration (see
// [DefaultErrorMapper]).
func NewAuthenticationInterceptor(engine security.Engine, opts ...Option) *AuthenticationInterceptor {
	cfg := buildConfig(opts...)

	return &AuthenticationInterceptor{engine: engine, cfg: cfg, mapper: cfg.ownMapper()}
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
			return nil, withStaged(i.mapper.Map(withBearerToken(ctx, req.Header()), err), carrier)
		}

		resp, err := next(withErrorMapper(newCtx, i.mapper), req)
		if resp != nil {
			flushHeader(resp.Header(), carrier.ResponseHeader())
		} else {
			err = withStaged(err, carrier)
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

		flushHeader(conn.ResponseHeader(), carrier.ResponseHeader())

		if err != nil {
			return i.mapper.Map(withBearerToken(ctx, conn.RequestHeader()), err)
		}

		return next(withErrorMapper(newCtx, i.mapper), conn) //nolint:wrapcheck // the handler error is the terminal wire value
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
