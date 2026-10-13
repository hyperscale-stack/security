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

// latinBases are the letters lodash's camelCase reads as ASCII letters —
// its deburr, over the Latin-1 Supplement and Latin Extended-A blocks
// (lodash 4.17.21, every letter of both): "émail" is camel-cased to email.
// Each string lists, in both cases, the letters keyed as its key.
var latinBases = map[string]string{
	"A":  "\u00c0\u00c1\u00c2\u00c3\u00c4\u00c5\u00e0\u00e1\u00e2\u00e3\u00e4\u00e5\u0100\u0101\u0102\u0103\u0104\u0105",
	"AE": "\u00c6\u00e6",
	"C":  "\u00c7\u00e7\u0106\u0107\u0108\u0109\u010a\u010b\u010c\u010d",
	"D":  "\u00d0\u00f0\u010e\u010f\u0110\u0111",
	"E":  "\u00c8\u00c9\u00ca\u00cb\u00e8\u00e9\u00ea\u00eb\u0112\u0113\u0114\u0115\u0116\u0117\u0118\u0119\u011a\u011b",
	"G":  "\u011c\u011d\u011e\u011f\u0120\u0121\u0122\u0123",
	"H":  "\u0124\u0125\u0126\u0127",
	"I":  "\u00cc\u00cd\u00ce\u00cf\u00ec\u00ed\u00ee\u00ef\u0128\u0129\u012a\u012b\u012c\u012d\u012e\u012f\u0130\u0131",
	"IJ": "\u0132\u0133",
	"J":  "\u0134\u0135",
	"K":  "\u0136\u0137\u0138",
	"L":  "\u0139\u013a\u013b\u013c\u013d\u013e\u013f\u0140\u0141\u0142",
	"N":  "\u00d1\u00f1\u0143\u0144\u0145\u0146\u0147\u0148\u0149\u014a\u014b",
	"O":  "\u00d2\u00d3\u00d4\u00d5\u00d6\u00d8\u00f2\u00f3\u00f4\u00f5\u00f6\u00f8\u014c\u014d\u014e\u014f\u0150\u0151",
	"OE": "\u0152\u0153",
	"R":  "\u0154\u0155\u0156\u0157\u0158\u0159",
	"S":  "\u015a\u015b\u015c\u015d\u015e\u015f\u0160\u0161\u017f",
	"SS": "\u00df",
	"T":  "\u0162\u0163\u0164\u0165\u0166\u0167",
	"TH": "\u00de\u00fe",
	"U":  "\u00d9\u00da\u00db\u00dc\u00f9\u00fa\u00fb\u00fc\u0168\u0169\u016a\u016b\u016c\u016d\u016e\u016f\u0170\u0171\u0172\u0173",
	"W":  "\u0174\u0175",
	"Y":  "\u00dd\u00fd\u00ff\u0176\u0177\u0178",
	"Z":  "\u0179\u017a\u017b\u017c\u017d\u017e",
}

// keyBases maps the foldRune of every letter of fullCaseExpansions and
// latinBases to its key.
var keyBases = newKeyBases()

func newKeyBases() map[rune]string {
	bases := map[rune]string{}

	for r, base := range fullCaseExpansions {
		bases[foldRune(r)] = base
	}

	for base, letters := range latinBases {
		for _, r := range letters {
			bases[foldRune(r)] = base
		}
	}

	return bases
}

// claimKey returns the case-insensitive key of a claim name: two names are
// "case variants" of each other — in this package's documentation — when
// their keys are equal. The key holds letters and decimal digits, and "#"
// (the language-tag delimiter): it ignores every other character —
// punctuation, symbols, white space, controls, invisible format characters
// and marks — and the letters ª, µ and º, which lodash's camelCase splits
// words on. It reads the Latin letters of latinBases as their ASCII
// letters (é as E, æ as AE), expands the nine code points of
// fullCaseExpansions, and maps every other letter to the smallest rune
// among the simple case-folding orbits of itself, of its simple uppercase
// and of its simple lowercase mapping; a rune and its case variants are
// kept or ignored together (the micro sign with the Greek mu, the iota
// subscript with the Greek iota). It therefore equates what relying
// parties matching names case-insensitively equate: Go's encoding/json
// (strings.EqualFold, so ſ with s and K with k), encoding/json/v2 with
// case:ignore (EqualFold, "_" and "-" ignored), camelCase key normalizers
// — lodash camelCase, camelcase-keys, humps — splitting words on
// punctuation, white space and invisible characters ("email.verified" and
// "email\u2010verified" read as emailVerified) and, for lodash, stripping
// the diacritics of Latin letters ("émail" read as email), Java's
// equalsIgnoreCase and Turkic-locale lowercasing (İ and ı with i), .NET's
// OrdinalIgnoreCase and Jackson's case-insensitive mode (ASCII case, and K
// for Jackson), and full-mapping upper-casing (ß with ss). An invalid
// UTF-8 byte reads as U+FFFD, which encoding/json writes in its place: a
// symbol, ignored.
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
		if r < utf8.RuneSelf {
			if keyed(r) {
				key.WriteRune(foldRune(r))
			}

			continue
		}

		f := foldRune(r)

		if base, ok := keyBases[f]; ok {
			key.WriteString(base)
		} else if lettered(f) {
			key.WriteRune(f)
		}
	}

	return key.String()
}

// lettered reports whether claimKey keeps a non-ASCII rune whose foldRune
// is f: a letter or a decimal digit, but the Latin-1 letters ª, µ and º,
// which lodash's camelCase splits words on. Deciding on f decides alike
// for every case variant of the rune.
func lettered(f rune) bool {
	return (unicode.IsLetter(f) || unicode.IsDigit(f)) && (f < 0x80 || f > 0xbf)
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
