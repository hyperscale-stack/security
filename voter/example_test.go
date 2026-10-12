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

// Example shows the canonical authorization pipeline: the attributes name
// what the resource requires, and each voter of the decision manager votes
// on the attributes it supports — its family and its value — comparing them
// with the authentication.
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

// Example_compose demonstrates the And/Or/Not combinators. A composite votes
// on the attributes its inner voters support, and And grants only when every
// inner voter grants: list one attribute per inner requirement.
func Example_compose() {
	adm := security.NewAffirmativeDecisionManager(
		voter.And(
			voter.Authenticated(),
			voter.HasAnyRole("ADMIN", "MANAGER"),
			voter.Not(voter.HasRole("BANNED")),
		),
	)

	managerRoute := []security.Attribute{security.IsAuthenticated, security.Role("MANAGER"), security.Role("BANNED")}
	adminRoute := []security.Attribute{security.IsAuthenticated, security.Role("ADMIN"), security.Role("BANNED")}

	manager := newAuth("bob", "ROLE_MANAGER")
	bannedManager := newAuth("eve", "ROLE_MANAGER", "ROLE_BANNED")

	fmt.Println("manager:", adm.Decide(context.Background(), manager, managerRoute))
	fmt.Println("banned manager:", adm.Decide(context.Background(), bannedManager, managerRoute))
	fmt.Println("manager on the admin route:", adm.Decide(context.Background(), manager, adminRoute))

	// Output:
	// manager: <nil>
	// banned manager: security: access denied
	// manager on the admin route: security: access denied
}
