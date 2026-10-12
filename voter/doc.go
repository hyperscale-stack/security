// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package voter ships the catalog of stock [security.Voter]
// implementations consumed by [security.AccessDecisionManager].
//
// The attributes a route lists name its requirements; each voter is bound to
// values and votes only on the attributes whose family and value it supports
// (Spring Security's RoleVoter semantics): HasRole("ADMIN") votes on
// security.Role("ADMIN") and abstains on security.Role("USER"), so one
// decision manager can safely serve several routes. Authenticated and
// Anonymous vote only on the security.IsAuthenticated and
// security.IsAnonymous attributes. Compose voters through And (strict: every
// inner voter must grant), Or and Not (which never grants an unauthenticated
// principal) for richer policies.
//
// Voters are pure (no I/O) and safe for concurrent use.
package voter
