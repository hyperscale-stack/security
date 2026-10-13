// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package oidcstack_test checks this repository's OpenID Connect stack
// end to end — the relying party of oidc/client against the provider of
// oidc/provider — and runs the client's transaction stores on real
// PostgreSQL, MySQL and Redis servers (opt-in, run in CI by
// scripts/test-backends.sh). The module holds tests only; they import no
// third-party OpenID Connect, OAuth 2.0 or JOSE library, so that their
// evidence is not mediated by one — the client's own go-jose is part of
// the code under test.
package oidcstack_test
