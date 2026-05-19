// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

// Profile selects the security baseline the [Server] applies. Three values
// are supported:
//
//   - Profile20      — vanilla RFC 6749. Allows implicit and password
//     grants when explicitly registered; PKCE is opt-in.
//   - Profile20BCP   — IETF draft-ietf-oauth-security-topics ("OAuth 2.0
//     Security Best Current Practice"). Refuses implicit
//     and password grants outright; mandates PKCE on
//     authorization_code; mandates refresh-token
//     rotation.
//   - Profile21Draft — draft-ietf-oauth-v2-1. Same constraints as BCP plus
//     an explicit prohibition of "plain" PKCE.
//
// The recommended default is [Profile20BCP].
type Profile int

// Profile enumerations. The zero value is Profile20BCP so the "I forgot to
// pick a profile" deployment lands on a safe baseline.
const (
	Profile20BCP   Profile = iota // recommended default
	Profile20                     // vanilla RFC 6749 (legacy grants allowed)
	Profile21Draft                // OAuth 2.1 draft (strictest)
)

// String makes Profile satisfy fmt.Stringer; values match the metadata
// document published at /.well-known/oauth-authorization-server.
func (p Profile) String() string {
	switch p {
	case Profile20:
		return "oauth2.0"
	case Profile20BCP:
		return "oauth2.0-bcp"
	case Profile21Draft:
		return "oauth2.1-draft"
	default:
		return "unknown"
	}
}

// AllowsLegacyGrant reports whether the profile permits the legacy
// password / implicit grants. Only [Profile20] does.
func (p Profile) AllowsLegacyGrant() bool { return p == Profile20 }

// RequiresPKCE reports whether the profile mandates PKCE on
// authorization_code. True for BCP and 21-draft.
func (p Profile) RequiresPKCE() bool { return p != Profile20 }

// RequiresRefreshRotation reports whether the profile mandates refresh-
// token rotation. True for BCP and 21-draft.
func (p Profile) RequiresRefreshRotation() bool { return p != Profile20 }

// AllowsPKCEPlain reports whether the profile tolerates the "plain" PKCE
// method (RFC 7636 §4.2). Only Profile20 does; BCP and 21-draft mandate S256.
func (p Profile) AllowsPKCEPlain() bool { return p == Profile20 }
