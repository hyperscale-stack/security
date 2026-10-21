// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider

import (
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClaimKey pins the names claimKey equates — the case variants
// relying parties confuse — and those it keeps apart.
func TestClaimKey(t *testing.T) {
	t.Parallel()

	same := [][]string{
		{"sub", "SUB", "Sub", "\u017fub", "\u017fUB", "s_ub", "S-U-B", "s__u--b"},                      // long s (EqualFold), delimiters (json/v2)
		{"iss", "ISS", "\u0131ss", "\u0130SS", "i\u00df", "I\u1e9e", "i-s-s"},                          // dotless and dotted i, sharp s
		{"nickname", "NICKNAME", "nic\u212aname"},                                                      // Kelvin sign
		{"profile", "PROFILE", "pro\ufb01le"},                                                          // fi ligature
		{"address", "ADDRESS", "addre\u00df"},                                                          // sharp s
		{"email_verified", "EmailVerified", "email-verified", "email_veri\ufb01ed"},                    // delimiters, fi ligature
		{"office", "o\ufb03ce", "O\ufb00ICE"},                                                          // ffi, ff ligatures
		{"waffle", "wa\ufb04e"},                                                                        // ffl ligature
		{"flow", "\ufb02ow"},                                                                           // fl ligature
		{"stable", "\ufb06able", "\ufb05able"},                                                         // st, long s t ligatures
		{"name#fr", "NAME#FR", "name#Fr", "na_me#fr", "name.fr", "namefr"},                             // language tags: # is a separator
		{"email_verified", "email_verified#", "email_verified#-", "email#verified", "email_veri#fied"}, // lodash and change-case split on #
		{"name", "name#"}, {"ab", "a#b"}, {"fr", "#fr"},
		{"a\xff", "a\xfe", "a\ufffd", "a"}, // invalid UTF-8: U+FFFD
		{"email_verified", "email.verified", "email verified", "Email~Verified", "e.m.a.i.l/verified"}, // camelCase normalizers
		{"email_verified", "email\u00a0verified", "email\u3000verified", "email\tverified"},            // white space
		{"auth_time", "auth~time", "auth.time", "auth time", "AUTH\x00TIME", "auth\x7ftime"},           // punctuation, controls
		{"given_name", "givenName", "given-name", "given name", "Given.Name", "@given$name!"},
		{"email_verified", "email\u2010verified", "email\u00b7verified", "email\u00adverified", "email\u2024verified"}, // Unicode punctuation (lodash camelCase)
		{"email_verified", "email\u200bverified", "email\ufeffverified", "email\u2019verified", "email\u0085verified"}, // invisible, apostrophe, C1 control
		{"auth_time", "auth\u2010time", "auth\u180etime", "auth\u00d7time"},                                            // hyphen, vowel separator, times sign
		{"email", "\u00e9mail", "\u00c9MAIL", "e\u0301mail", "e\u0301\u0327mail"},                                      // lodash deburr: Latin letters, combining marks
		{"aether", "\u00e6ther", "\u00c6THER"}, {"thing", "\u00feing"}, {"oeuvre", "\u0153uvre"},                       // deburred to two letters
		{"ylang", "\u00fflang", "\u0178LANG"}, {"kappa", "\u0138appa"}, {"name", "\u0149ame"}, // y diaeresis, kra, n preceded by apostrophe
		{"aa", "\u212ba", "\u00e5A"},                                       // Angstrom sign, a ring
		{"ab", "a\u00aab", "a\u00bab", "a\u00b5b", "a\u03bcb", "a\u039cb"}, // ordinals and micro sign (lodash splits), Greek mu
		{"ab", "a\u0345b", "a\u03b9b", "a\u0399b"},
		{"claim", "claim\u2460", "claim\u00b2", "claim\u2163"}, // numbers but decimal digits                         // iota subscript (lodash drops), Greek iota
	}

	for _, group := range same {
		for _, name := range group[1:] {
			assert.Equal(t, claimKey(group[0]), claimKey(name), "%q and %q", group[0], name)
		}
	}

	different := [][2]string{
		{"sub", "subs"}, {"name#fr", "name#de"}, {"claim1", "claim2"},
		{"s", "\u00df"}, {"sub", "\u0455ub"}, {"sub", "\uff53ub"}, {"s", "\u1e61"}, {"claim", "claim\u0661"},
	}

	for _, pair := range different {
		assert.NotEqual(t, claimKey(pair[0]), claimKey(pair[1]), "%q and %q", pair[0], pair[1])
	}
}

// TestFoldRuneIsAClassKey: over every rune with a case mapping — every
// other rune is a fixed point of all four mappings — foldRune is the same
// for a rune and its simple case folding, uppercase, lowercase and
// titlecase mappings, so it keys the classes these mappings connect; and
// exactly four non-ASCII runes key as ASCII: İ, ı, ſ and the Kelvin sign.
func TestFoldRuneIsAClassKey(t *testing.T) {
	t.Parallel()

	var asciiKeyed []rune

	for _, cr := range unicode.CaseRanges {
		for r := rune(cr.Lo); r <= rune(cr.Hi); r++ {
			key := foldRune(r)

			for _, mapped := range []rune{unicode.SimpleFold(r), unicode.ToUpper(r), unicode.ToLower(r), unicode.ToTitle(r)} {
				require.Equal(t, key, foldRune(mapped), "U+%04X and U+%04X", r, mapped)
			}

			if r >= utf8.RuneSelf && key < utf8.RuneSelf {
				asciiKeyed = append(asciiKeyed, r)
			}
		}
	}

	assert.Equal(t, []rune{0x130, 0x131, 0x17f, 0x212a}, asciiKeyed)
}

// TestASCIIClaimKeyIsTheUnicodeKey: the ASCII fast path computes the key
// of the general one for every ASCII name of one or two bytes, and declines
// any other name.
func TestASCIIClaimKeyIsTheUnicodeKey(t *testing.T) {
	t.Parallel()

	for a := range utf8.RuneSelf {
		for b := -1; b < utf8.RuneSelf; b++ {
			name := string(rune(a))
			if b >= 0 {
				name += string(rune(b))
			}

			key, ok := asciiClaimKey(name)
			require.True(t, ok, "%q", name)
			require.Equal(t, unicodeClaimKey(name), key, "%q", name)
		}
	}

	_, ok := asciiClaimKey("\u017fub")
	assert.False(t, ok)
}

// TestClaimKeyIgnoresWhatLodashCamelCaseDrops: every character outside ASCII
// that lodash's camelCase (4.17.21) splits words on — its rsBreakRange — or
// removes — its apostrophe, and the combining marks its deburr strips — is
// ignored: "email" + c + "verified" keys as email_verified.
func TestClaimKeyIgnoresWhatLodashCamelCaseDrops(t *testing.T) {
	t.Parallel()

	ranges := [][2]rune{
		{0x80, 0xbf}, {0xd7, 0xd7}, {0xf7, 0xf7}, // rsNonCharRange, rsMathOpRange
		{0x2000, 0x206f},                                                       // rsPunctuationRange, the apostrophe U+2019
		{0x1680, 0x1680}, {0x180e, 0x180e}, {0x3000, 0x3000}, {0xfeff, 0xfeff}, // rsSpaceRange
		{0x300, 0x36f}, {0xfe20, 0xfe2f}, {0x20d0, 0x20ff}, // rsComboRange
	}

	want := claimKey("email_verified")

	for _, bounds := range ranges {
		for r := bounds[0]; r <= bounds[1]; r++ {
			require.Equal(t, want, claimKey("email"+string(r)+"verified"), "U+%04X", r)
		}
	}
}

// TestClaimKeyReadsLatinLettersAsASCII: every letter lodash's deburr reads
// as ASCII — the Latin-1 Supplement and Latin Extended-A letters, × and ÷
// aside — keys as ASCII letters, and so do the letters of
// fullCaseExpansions.
func TestClaimKeyReadsLatinLettersAsASCII(t *testing.T) {
	t.Parallel()

	letters := []rune{0xdf, 0x1e9e, 0xfb00, 0xfb01, 0xfb02, 0xfb03, 0xfb04, 0xfb05, 0xfb06}

	for r := rune(0xc0); r <= 0x17f; r++ {
		if r != 0xd7 && r != 0xf7 {
			letters = append(letters, r)
		}
	}

	for _, r := range letters {
		key := claimKey(string(r))
		require.NotEmpty(t, key, "U+%04X", r)

		for i := range len(key) {
			require.True(t, 'A' <= key[i] && key[i] <= 'Z', "U+%04X keys as %q", r, key)
		}
	}

	for base, listed := range latinBases {
		for _, r := range listed {
			assert.Equal(t, base, claimKey(string(r)), "U+%04X", r)
		}
	}

	for r, base := range fullCaseExpansions {
		assert.Equal(t, base, claimKey(string(r)), "U+%04X", r)
	}
}

// TestClaimKeyIsTheSameForCaseVariants: over every rune with a case
// mapping, claimKey equates a rune with its simple case folding,
// uppercase, lowercase and titlecase mappings — what it ignores, it
// ignores with all of them (the micro sign with the Greek mu, the iota
// subscript with the Greek iota).
func TestClaimKeyIsTheSameForCaseVariants(t *testing.T) {
	t.Parallel()

	for _, cr := range unicode.CaseRanges {
		for r := rune(cr.Lo); r <= rune(cr.Hi); r++ {
			key := claimKey("a" + string(r) + "b")

			for _, mapped := range []rune{unicode.SimpleFold(r), unicode.ToUpper(r), unicode.ToLower(r), unicode.ToTitle(r)} {
				require.Equal(t, key, claimKey("a"+string(mapped)+"b"), "U+%04X and U+%04X", r, mapped)
			}
		}
	}
}
