// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package httpsec is the net/http transport adapter for the security core.
//
// It wires the transport-agnostic primitives of the core (Carrier, Extractor,
// Authenticator, Engine, AccessDecisionManager) into standard net/http
// middleware chains. The middleware can be plugged into any router that
// accepts http.Handler — net/http.ServeMux, chi, gorilla/mux, gin's http
// adapter, etc.
//
// Allowed dependencies:
//   - github.com/hyperscale-stack/security (core)
//   - go.opentelemetry.io/otel
//   - stdlib only
//
// Forbidden dependencies: gRPC, any HTTP router (the package is router-
// agnostic), any concrete logger.
package httpsec
