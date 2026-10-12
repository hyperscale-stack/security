// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security

import "context"

// Attribute names one requirement of a resource: the role, scope,
// authority, permission or authentication state an access decision must
// check. The attributes a route lists are the policy — each [Voter] of the
// [AccessDecisionManager] votes on the attributes it supports, comparing
// their value with the authentication, and an attribute that no voter
// supports denies the decision. Five concrete attributes are shipped below;
// applications can define their own (they just need to implement String()).
type Attribute interface {
	// String returns a stable, log-friendly form of the attribute. It is used
	// by [AccessDecisionManager] for OTel attributes; it MUST NOT include
	// any secret or PII.
	String() string
}

// RoleAttribute names a role expected on the authenticated principal. Roles
// use the Spring Security "ROLE_" prefix at the wire level (in OTel
// attributes and in custom Authorities() slices) but the constructor
// accepts the bare name to keep usage idiomatic.
type RoleAttribute string

// String implements [Attribute]. Output is "ROLE_<name>" — Spring-compatible
// for ops tooling that already keys off that convention.
func (r RoleAttribute) String() string { return rolePrefix + string(r) }

// Name returns the bare role name (without the ROLE_ prefix).
func (r RoleAttribute) Name() string { return string(r) }

// Role constructs a [RoleAttribute] from a bare role name.
func Role(name string) Attribute { return RoleAttribute(name) }

const rolePrefix = "ROLE_"

// ScopeAttribute names an OAuth2 scope expected on the authenticated
// principal. Scope names follow the RFC 6749 §3.3 grammar but this type
// stays format-agnostic.
type ScopeAttribute string

// String implements [Attribute]. Output is "scope:<name>".
func (s ScopeAttribute) String() string { return "scope:" + string(s) }

// Name returns the bare scope name.
func (s ScopeAttribute) Name() string { return string(s) }

// Scope constructs a [ScopeAttribute].
func Scope(name string) Attribute { return ScopeAttribute(name) }

// AuthorityAttribute names a free-form authority string. Unlike
// [RoleAttribute] it carries no convention — the configured voter compares
// the value verbatim against [Authentication.Authorities].
type AuthorityAttribute string

// String implements [Attribute]. Output is the bare authority name.
func (a AuthorityAttribute) String() string { return string(a) }

// Authority constructs an [AuthorityAttribute].
func Authority(name string) Attribute { return AuthorityAttribute(name) }

// PermissionAttribute carries an arbitrary predicate evaluated by the
// permission voter. It is the escape hatch for application-specific
// authorization (ABAC, ownership checks, time-of-day windows, ...).
// The predicate MUST be pure (no I/O) and safe for concurrent use.
type PermissionAttribute struct {
	// Name is the human-readable label of the permission. It populates the
	// OTel attributes; keep it stable across deployments.
	Name string
	// Predicate is invoked by the permission voter with the live
	// authentication. A nil predicate is treated as DecisionDeny.
	Predicate func(ctx context.Context, auth Authentication) bool
}

// String implements [Attribute]. Output is "permission:<Name>".
func (p PermissionAttribute) String() string { return "permission:" + p.Name }

// Permission constructs a [PermissionAttribute] in one call.
func Permission(name string, predicate func(ctx context.Context, auth Authentication) bool) Attribute {
	return PermissionAttribute{Name: name, Predicate: predicate}
}

// StateAttribute requires a state of the authentication itself rather than
// an authority. The voter package's Authenticated and Anonymous voters
// evaluate it, and no other stock voter does.
type StateAttribute string

const (
	// IsAuthenticated requires an authenticated principal.
	IsAuthenticated StateAttribute = "authenticated"
	// IsAnonymous requires an unauthenticated request — e.g. a signup or
	// password-reset request page reserved to logged-out clients.
	IsAnonymous StateAttribute = "anonymous"
)

// String implements [Attribute]. Output is "state:<state>".
func (s StateAttribute) String() string { return "state:" + string(s) }
