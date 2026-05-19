// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security

// Attribute is an opaque authorisation predicate carried alongside a request.
// Voters opt-in via [Voter.Supports] and inspect the concrete type through
// type switches.
//
// Concrete attribute types live in Phase 5 (RoleAttribute, ScopeAttribute,
// AuthorityAttribute, PermissionAttribute). The interface stays here so the
// [Voter] and [AccessDecisionManager] contracts can refer to it from Phase 2.
type Attribute interface {
	// String returns a stable, log-friendly form of the attribute. It is used
	// by [AccessDecisionManager] for OTel attributes; it MUST NOT include
	// any secret or PII.
	String() string
}
