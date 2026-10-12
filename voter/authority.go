// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package voter

import (
	"slices"

	"github.com/hyperscale-stack/security"
)

// HasAuthority returns a [security.Voter] bound to one authority: it votes on
// the [security.AuthorityAttribute] naming that authority and abstains on
// every other attribute. It grants when the authenticated principal carries
// the authority verbatim — no prefix normalisation (use [HasRole] /
// [HasScope] when you want the conventions of those types).
func HasAuthority(name string) security.Voter {
	return newAuthorityVoter(name)
}

// HasAnyAuthority returns a [security.Voter] bound to several authorities: it
// grants when the principal carries at least one of the authorities the
// route requests.
func HasAnyAuthority(names ...string) security.Voter {
	return newAuthorityVoter(names...)
}

func newAuthorityVoter(names ...string) security.Voter {
	return nameVoter{names: slices.Clone(names), nameOf: authorityName, holds: slices.Contains[[]string]}
}

// authorityName returns the name of an authority attribute.
func authorityName(a security.Attribute) (string, bool) {
	n, ok := a.(security.AuthorityAttribute)

	return string(n), ok
}
