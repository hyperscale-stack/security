// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package voter

import (
	"context"
	"slices"

	"github.com/hyperscale-stack/security"
)

// HasAuthority returns a [security.Voter] that grants when the authenticated
// principal carries the given authority verbatim. No prefix normalisation
// (use [HasRole] / [HasScope] when you want the conventions of those types).
func HasAuthority(name string) security.Voter {
	return authorityVoter{wanted: []string{name}, anyOf: false}
}

// HasAnyAuthority grants when the principal carries at least one of the
// listed authorities.
func HasAnyAuthority(names ...string) security.Voter {
	return authorityVoter{wanted: names, anyOf: true}
}

type authorityVoter struct {
	wanted []string
	anyOf  bool
}

func (v authorityVoter) Supports(a security.Attribute) bool {
	_, ok := a.(security.AuthorityAttribute)

	return ok
}

func (v authorityVoter) Vote(_ context.Context, auth security.Authentication, _ []security.Attribute) security.Decision {
	if !auth.IsAuthenticated() {
		return security.DecisionDeny
	}

	for _, want := range v.wanted {
		if slices.Contains(auth.Authorities(), want) {
			return security.DecisionGrant
		}

		if !v.anyOf {
			break
		}
	}

	return security.DecisionDeny
}
