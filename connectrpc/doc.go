// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package connectrpcsec is the ConnectRPC transport adapter for the security
// core.
//
// It exposes connect.Interceptor values that hand the request headers (the
// Carrier) to the core Engine and map security errors to the appropriate
// Connect error codes (connect.CodeUnauthenticated, connect.CodePermissionDenied,
// …).
//
// ConnectRPC has a single Interceptor interface covering both unary and
// streaming RPCs, installed once via connect.WithInterceptors. The adapter
// therefore exposes two interceptors instead of the four gRPC-style
// constructors: NewAuthenticationInterceptor authenticates every inbound RPC
// and NewAuthorizationInterceptor enforces an access decision manager.
//
// Allowed dependencies:
//   - github.com/hyperscale-stack/security (core)
//   - connectrpc.com/connect
//   - go.opentelemetry.io/otel
//   - stdlib only
package connectrpcsec
