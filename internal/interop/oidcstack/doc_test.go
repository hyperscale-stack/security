// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package oidcstack_test checks this repository's OpenID Connect stack
// end to end — the relying party of oidc/client against the provider of
// oidc/provider — and runs the client's transaction stores on real
// PostgreSQL, MySQL and Redis servers (opt-in). The module holds tests
// only; it depends on no third-party OpenID Connect or JOSE library, so
// that its evidence is not mediated by one.
package oidcstack_test
