// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// fullCaseExpansions are the nine code points whose full case mapping
// (Unicode SpecialCasing) is pure ASCII while their simple mappings are
// not: upper-casing with full mappings (JavaScript's, Java's and Python's
// toUpperCase and upper) and Python's casefold read "iß" as "ISS" and
// "proﬁle" as "PROFILE".
var fullCaseExpansions = map[rune]string{
	'\u00df': "SS", '\u1e9e': "SS", // sharp s, capital sharp s
	'\ufb00': "FF", '\ufb01': "FI", '\ufb02': "FL", '\ufb03': "FFI", '\ufb04': "FFL", // ff, fi, fl, ffi, ffl ligatures
	'\ufb05': "ST", '\ufb06': "ST", // long s t, s t ligatures
}

// claimKey returns the case-insensitive key of a claim name: two names are
// "case variants" of each other — in this package's documentation — when
// their keys are equal. The key ignores every ASCII character but letters,
// digits and "#" (the language-tag delimiter) and Unicode white space,
// expands the nine code points of fullCaseExpansions and maps every other
// rune to the smallest rune among the simple case-folding orbits of
// itself, of its simple uppercase and of its simple lowercase mapping. It
// therefore equates what relying parties matching names case-insensitively
// equate: Go's encoding/json (strings.EqualFold, so ſ with s and K with k),
// encoding/json/v2 with case:ignore (EqualFold, "_" and "-" ignored),
// camelCase key normalizers — lodash camelCase, camelcase-keys, humps —
// splitting words on punctuation and white space ("email.verified" read as
// emailVerified), Java's equalsIgnoreCase and Turkic-locale lowercasing (İ
// and ı with i), .NET's OrdinalIgnoreCase and Jackson's case-insensitive
// mode (ASCII case, and K for Jackson), and full-mapping upper-casing (ß
// with ss). An invalid UTF-8 byte keys as U+FFFD, which encoding/json
// writes in its place.
//
// It is wider than the strings.EqualFold key of the oidc/client and jwt
// verifiers on purpose: a verifier is safe when its own decoder cannot be
// confused; an emitter must be safe for every relying party.
func claimKey(name string) string {
	if key, ok := asciiClaimKey(name); ok {
		return key
	}

	return unicodeClaimKey(name)
}

// asciiClaimKey is claimKey for an ASCII name, false for any other name.
func asciiClaimKey(name string) (string, bool) {
	key := make([]byte, 0, len(name))

	for i := range len(name) {
		switch c := name[i]; {
		case c >= utf8.RuneSelf:
			return "", false
		case 'a' <= c && c <= 'z':
			key = append(key, c-('a'-'A'))
		case keyed(rune(c)):
			key = append(key, c)
		}
	}

	return string(key), true
}

// keyed reports whether an ASCII rune counts in a claim key: a letter, a
// digit or "#".
func keyed(r rune) bool {
	return 'A' <= r && r <= 'Z' || 'a' <= r && r <= 'z' || '0' <= r && r <= '9' || r == '#'
}

// unicodeClaimKey is claimKey for any name.
func unicodeClaimKey(name string) string {
	var key strings.Builder

	key.Grow(len(name))

	for _, r := range name {
		if r < utf8.RuneSelf && !keyed(r) || unicode.IsSpace(r) {
			continue
		}

		if expansion, ok := fullCaseExpansions[r]; ok {
			key.WriteString(expansion)

			continue
		}

		key.WriteRune(foldRune(r))
	}

	return key.String()
}

// foldRune returns the smallest rune among the simple case-folding orbits
// of r, of its simple uppercase and of its simple lowercase mapping — the
// same rune for every rune these mappings connect.
func foldRune(r rune) rune {
	return min(orbitMin(r), orbitMin(unicode.ToUpper(r)), orbitMin(unicode.ToLower(r)))
}

// orbitMin returns the smallest rune of the simple case-folding orbit of r
// (unicode.SimpleFold).
func orbitMin(r rune) rune {
	smallest := r

	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		smallest = min(smallest, f)
	}

	return smallest
}

// untagged returns name without its language tag (Core §5.2): "name#fr"
// is name.
func untagged(name string) string {
	base, _, _ := strings.Cut(name, "#")

	return base
}

// keySet returns the claimKeys of names.
func keySet(names []string) map[string]struct{} {
	keys := make(map[string]struct{}, len(names))
	for _, name := range names {
		keys[claimKey(name)] = struct{}{}
	}

	return keys
}

// authorizationClaims are the authorization claims of RFC 9068 §2.2.3.1,
// registered in the JWT Claims registry (§7.2): the provider knows them as
// it knows the standard claims.
var authorizationClaims = []string{"roles", "groups", "entitlements"}

// claimNames maps the claimKey of every claim the provider knows — the
// standard claims of Core §5.1 (those of the scopes, §5.4), the
// authorization claims of RFC 9068 and Config.ClaimsSupported — to its
// exact spelling, untagged.
type claimNames map[string]string

// newClaimNames returns the known claims, with the untagged names of
// supported (as Config.validate accepts them) but the reserved ones.
func newClaimNames(supported []string) claimNames {
	names := claimNames{}

	for _, scoped := range scopeClaims {
		for _, name := range scoped {
			names[claimKey(name)] = name
		}
	}

	for _, name := range authorizationClaims {
		names[claimKey(name)] = name
	}

	for _, name := range supported {
		if base := untagged(name); !reserved(base) {
			names[claimKey(base)] = base
		}
	}

	return names
}

// releasable reports whether the provider may release a claim requested
// under name: its untagged name is neither a reserved claim nor a case
// variant of one, nor a case variant of a known claim other than that
// claim's exact spelling — "SUB", "ſub#fr", "Email", "EMAIL#fr" and
// "Roles" are never released, "email#fr" is.
func (n claimNames) releasable(name string) bool {
	base := untagged(name)
	key := claimKey(base)

	if _, ok := reservedKeys[key]; ok {
		return false
	}

	exact, known := n[key]

	return !known || exact == base
}

// filter returns the claim requests of r the provider may release — what
// the Interaction is shown and the grant records — in their order.
func (n claimNames) filter(r ClaimsRequest) ClaimsRequest {
	return ClaimsRequest{IDToken: n.keep(r.IDToken), UserInfo: n.keep(r.UserInfo)}
}

func (n claimNames) keep(list []ClaimRequest) []ClaimRequest {
	if list == nil {
		return nil
	}

	kept := make([]ClaimRequest, 0, len(list))

	for _, c := range list {
		if n.releasable(c.Name) {
			kept = append(kept, c)
		}
	}

	return kept
}
