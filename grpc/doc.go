// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package grpcsec is the gRPC transport adapter for the security core.
//
// It exposes unary and stream server interceptors that hand the gRPC metadata
// (the Carrier) to the core Engine and map security errors to the appropriate
// gRPC status codes (codes.Unauthenticated, codes.PermissionDenied, …).
//
// Allowed dependencies:
//   - github.com/hyperscale-stack/security (core)
//   - google.golang.org/grpc
//   - go.opentelemetry.io/otel
//   - stdlib only
package grpcsec
