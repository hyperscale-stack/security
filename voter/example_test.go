// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package voter_test

import (
	"context"
	"fmt"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/voter"
)

// Example shows the canonical authorization pipeline: bind the expected
// permission into the voter at construction time and call Decide on the
// known authentication. Attributes are matched against Voter.Supports to
// activate the voter; the voter itself knows what to check.
func Example() {
	adminOnly := security.NewAffirmativeDecisionManager(
		voter.HasRole("ADMIN"),
	)
	writeMail := security.NewAffirmativeDecisionManager(
		voter.HasScope("write:mail"),
	)

	auth := newAuth("alice", "ROLE_ADMIN", "scope:read:mail")
	roleAttrs := []security.Attribute{security.Role("ADMIN")}
	scopeAttrs := []security.Attribute{security.Scope("write:mail")}

	fmt.Println("admin only:", adminOnly.Decide(context.Background(), auth, roleAttrs))
	fmt.Println("write:mail:", writeMail.Decide(context.Background(), auth, scopeAttrs))

	// Output:
	// admin only: <nil>
	// write:mail: security: access denied
}

// Example_compose demonstrates the And/Or/Not combinators.
func Example_compose() {
	adm := security.NewAffirmativeDecisionManager(
		voter.And(
			voter.Authenticated(),
			voter.HasAnyRole("ADMIN", "MANAGER"),
		),
	)

	auth := newAuth("bob", "ROLE_MANAGER")
	err := adm.Decide(context.Background(), auth, []security.Attribute{
		security.Role("ADMIN"),
	})
	fmt.Println("manager:", err)

	// Output:
	// manager: <nil>
}
