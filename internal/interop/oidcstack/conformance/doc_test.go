// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package conformance_test runs the OpenID Foundation conformance suite
// against this repository's OpenID Connect stack: oidc/provider as the
// provider under test of the OP plans (TestConformanceOPHelperProcess) and
// oidc/client as the relying party of the RP plans
// (TestConformanceRPPlans). Both are opt-in and driven by run.sh — without
// their environment they skip, so routine CI only compiles them. A local
// run of the suite is not an OpenID Certification and is not presented as
// one.
package conformance_test
