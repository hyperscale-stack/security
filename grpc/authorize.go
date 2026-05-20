// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grpcsec

import (
	"context"

	"github.com/hyperscale-stack/security"
	"go.opentelemetry.io/otel"
	"google.golang.org/grpc"
)

// UnaryAuthorize returns a unary interceptor that enforces an
// [security.AccessDecisionManager] against the request's
// [security.Authentication]. Install it AFTER [UnaryServerInterceptor] in
// the interceptor chain so the context already carries an authentication.
//
// On grant the handler runs; on deny the configured [ErrorMapper]
// translates the decision (typically codes.PermissionDenied).
func UnaryAuthorize(
	adm security.AccessDecisionManager,
	attrs []security.Attribute,
	opts ...Option,
) grpc.UnaryServerInterceptor {
	cfg := buildConfig(opts...)

	return func(
		ctx context.Context,
		req any,
		_ *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if err := decide(ctx, adm, attrs); err != nil {
			return nil, cfg.errorMapper.Map(ctx, err)
		}

		return handler(ctx, req)
	}
}

// StreamAuthorize is the streaming counterpart of [UnaryAuthorize].
func StreamAuthorize(
	adm security.AccessDecisionManager,
	attrs []security.Attribute,
	opts ...Option,
) grpc.StreamServerInterceptor {
	cfg := buildConfig(opts...)

	return func(
		srv any,
		ss grpc.ServerStream,
		_ *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		if err := decide(ss.Context(), adm, attrs); err != nil {
			return cfg.errorMapper.Map(ss.Context(), err)
		}

		return handler(srv, ss)
	}
}

// decide pulls the Authentication from ctx and runs the ADM, wrapping the
// call in a "grpcsec.Authorize" span.
func decide(ctx context.Context, adm security.AccessDecisionManager, attrs []security.Attribute) error {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "grpcsec.Authorize")
	defer span.End()

	auth, _ := security.FromContext(ctx)

	if err := adm.Decide(ctx, auth, attrs); err != nil {
		return err //nolint:wrapcheck // security.* sentinels pass through to the ErrorMapper
	}

	return nil
}
