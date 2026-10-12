// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package voter

import (
	"fmt"
	"slices"
	"strings"
)

// mustNames returns a copy of names after checking that the voter can match
// every one of them: a voter bound to no name, or to a name no authority
// can satisfy, is a programming error reported at construction rather than
// a requirement silently impossible to meet.
func mustNames(constructor, kind string, names []string, check func(string) error) []string {
	if len(names) == 0 {
		panic(fmt.Sprintf("voter: %s: no %s", constructor, kind))
	}

	for _, n := range names {
		if err := check(n); err != nil {
			panic(fmt.Sprintf("voter: %s: %v", constructor, err))
		}
	}

	return slices.Clone(names)
}

// checkRole accepts a non-empty bare role name.
func checkRole(name string) error {
	switch {
	case name == "":
		return errEmptyName("role")
	case strings.HasPrefix(name, rolePrefix):
		return fmt.Errorf("role %q must not start with %q", name, rolePrefix)
	default:
		return nil
	}
}

// checkScope accepts an RFC 6749 §3.3 scope-token — 1*( %x21 / %x23-5B /
// %x5D-7E ) — that does not already carry the scope prefix.
func checkScope(name string) error {
	if !isScopeToken(name) {
		return fmt.Errorf("scope %q is not an RFC 6749 scope-token", name)
	}

	if strings.HasPrefix(name, scopePrefix) {
		return fmt.Errorf("scope %q must not start with %q", name, scopePrefix)
	}

	return nil
}

// checkAuthority accepts any non-empty authority.
func checkAuthority(name string) error {
	if name == "" {
		return errEmptyName("authority")
	}

	return nil
}

func errEmptyName(kind string) error { return fmt.Errorf("empty %s", kind) }

// isScopeToken reports whether s is an RFC 6749 §3.3 scope-token.
func isScopeToken(s string) bool {
	if s == "" {
		return false
	}

	for i := range len(s) {
		c := s[i]
		if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}

	return true
}
