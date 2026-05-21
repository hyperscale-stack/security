// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package connectrpcsec

import (
	"context"

	"connectrpc.com/connect"
	"github.com/hyperscale-stack/security"
	"go.opentelemetry.io/otel"
)

// AuthorizationInterceptor is a [connect.Interceptor] that enforces a
// [security.AccessDecisionManager] against the request's
// [security.Authentication].
//
// Install it AFTER [NewAuthenticationInterceptor] in the
// connect.WithInterceptors(...) list so the context already carries an
// authentication: the first interceptor of the list is the outermost, so
// connect.WithInterceptors(authn, authz) runs authn (which enriches the
// context) before authz.
//
// On grant the handler runs; on deny the configured [ErrorMapper] translates
// the decision (typically connect.CodePermissionDenied).
type AuthorizationInterceptor struct {
	adm   security.AccessDecisionManager
	attrs []security.Attribute
	cfg   *config
}

// NewAuthorizationInterceptor builds a [connect.Interceptor] that enforces adm
// against attrs for every inbound unary and streaming RPC.
func NewAuthorizationInterceptor(
	adm security.AccessDecisionManager,
	attrs []security.Attribute,
	opts ...Option,
) *AuthorizationInterceptor {
	return &AuthorizationInterceptor{adm: adm, attrs: attrs, cfg: buildConfig(opts...)}
}

// Compile-time check.
var _ connect.Interceptor = (*AuthorizationInterceptor)(nil)

// WrapUnary implements [connect.Interceptor]. Outbound client calls are passed
// through untouched; inbound handler calls are authorized.
func (i *AuthorizationInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if req.Spec().IsClient {
			return next(ctx, req) //nolint:wrapcheck // pass-through: the client error is the terminal value
		}

		if err := decide(ctx, i.adm, i.attrs); err != nil {
			return nil, i.cfg.errorMapper.Map(ctx, err)
		}

		return next(ctx, req) //nolint:wrapcheck // the handler / connect error is the terminal wire value
	}
}

// WrapStreamingHandler implements [connect.Interceptor]. It runs the access
// decision before the handler runs.
func (i *AuthorizationInterceptor) WrapStreamingHandler(
	next connect.StreamingHandlerFunc,
) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		if err := decide(ctx, i.adm, i.attrs); err != nil {
			return i.cfg.errorMapper.Map(ctx, err)
		}

		return next(ctx, conn) //nolint:wrapcheck // the handler error is the terminal wire value
	}
}

// WrapStreamingClient implements [connect.Interceptor] as a pass-through; the
// access decision is server-side only.
func (i *AuthorizationInterceptor) WrapStreamingClient(
	next connect.StreamingClientFunc,
) connect.StreamingClientFunc {
	return next
}

// decide pulls the Authentication from ctx and runs the ADM, wrapping the call
// in a "connectrpcsec.Authorize" span.
func decide(ctx context.Context, adm security.AccessDecisionManager, attrs []security.Attribute) error {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "connectrpcsec.Authorize")
	defer span.End()

	auth, _ := security.FromContext(ctx)

	if err := adm.Decide(ctx, auth, attrs); err != nil {
		return err //nolint:wrapcheck // security.* sentinels pass through to the ErrorMapper
	}

	return nil
}
