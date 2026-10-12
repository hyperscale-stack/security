// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grpcsec

import (
	"github.com/hyperscale-stack/security"
	"google.golang.org/grpc"
)

// ServerOptions returns the grpc.ServerOption values that authenticate every
// RPC against engine — unary AND streaming. Chaining only
// [UnaryServerInterceptor] leaves the streaming RPCs (the health service's
// Watch, server reflection, your own streams) unauthenticated.
func ServerOptions(engine security.Engine, opts ...Option) []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(UnaryServerInterceptor(engine, opts...)),
		grpc.ChainStreamInterceptor(StreamServerInterceptor(engine, opts...)),
	}
}

// AuthorizeServerOptions returns the grpc.ServerOption values that enforce
// adm against attrs on every RPC — unary AND streaming. Pass them after
// [ServerOptions]: chained interceptors run in the order of the options, so
// the authentication runs first.
//
//	srv := grpc.NewServer(slices.Concat(
//	    grpcsec.ServerOptions(engine),
//	    grpcsec.AuthorizeServerOptions(adm, attrs),
//	)...)
//
// It panics if adm is nil.
func AuthorizeServerOptions(
	adm security.AccessDecisionManager,
	attrs []security.Attribute,
	opts ...Option,
) []grpc.ServerOption {
	mustDecisionManager(adm)

	return []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(UnaryAuthorize(adm, attrs, opts...)),
		grpc.ChainStreamInterceptor(StreamAuthorize(adm, attrs, opts...)),
	}
}
