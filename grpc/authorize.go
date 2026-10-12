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
	"google.golang.org/grpc"
)

// UnaryAuthorize returns a unary interceptor that enforces an
// [security.AccessDecisionManager] against the request's
// [security.Authentication]. Install it AFTER [UnaryServerInterceptor] in
// the interceptor chain so the context already carries an authentication,
// and install [StreamAuthorize] too — or use [AuthorizeServerOptions].
//
// On grant the handler runs. On deny it answers with its [WithErrorMapper],
// else the mapper of the authentication interceptor before it, else
// [DefaultErrorMapper]: codes.PermissionDenied for an authenticated
// principal, codes.Unauthenticated for an unauthenticated one. It panics if
// adm is nil.
func UnaryAuthorize(
	adm security.AccessDecisionManager,
	attrs []security.Attribute,
	opts ...Option,
) grpc.UnaryServerInterceptor {
	mustDecisionManager(adm)

	cfg := buildConfig(opts...)

	return func(
		ctx context.Context,
		req any,
		_ *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if err := decide(ctx, adm, attrs); err != nil {
			return nil, cfg.mapper(ctx).Map(ctx, err)
		}

		return handler(ctx, req)
	}
}

// StreamAuthorize is the streaming counterpart of [UnaryAuthorize]. It
// panics if adm is nil.
func StreamAuthorize(
	adm security.AccessDecisionManager,
	attrs []security.Attribute,
	opts ...Option,
) grpc.StreamServerInterceptor {
	mustDecisionManager(adm)

	cfg := buildConfig(opts...)

	return func(
		srv any,
		ss grpc.ServerStream,
		_ *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		if err := decide(ss.Context(), adm, attrs); err != nil {
			return cfg.mapper(ss.Context()).Map(ss.Context(), err)
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
		return refusal(auth, err)
	}

	return nil
}

// refusal turns an access denial of an unauthenticated principal into
// "authentication required" (codes.Unauthenticated): the caller lacks
// credentials. Any other error passes through.
func refusal(auth security.Authentication, err error) error {
	denied := errors.Is(err, security.ErrAccessDenied) || errors.Is(err, security.ErrInsufficientScope)
	if denied && !auth.IsAuthenticated() {
		return fmt.Errorf("%w: %w", security.ErrAuthenticationRequired, err)
	}

	return err //nolint:wrapcheck // security.* sentinels pass through to the ErrorMapper
}

func mustDecisionManager(adm security.AccessDecisionManager) {
	if adm == nil {
		panic("grpcsec: nil AccessDecisionManager")
	}
}
