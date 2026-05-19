// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package examples is a container module hosting the use-case examples
// shipped alongside the security library. Each example is a sub-package with
// a runnable main and a README documenting the curl/grpc probes.
//
// The examples module is free to depend on every other module of the
// workspace (this is the only place where doing so is acceptable).
//
// Real examples land progressively: basic-http (Phase 4), bearer-jwt
// (Phase 6), oauth2-server / oauth2-resource-server (Phase 7-8), grpc-bearer
// (Phase 9), session-web (Phase 10), multi-tenant (Phase 11).
package examples
