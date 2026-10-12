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
		{"sub", "SUB", "Sub", "\u017fub", "\u017fUB", "s_ub", "S-U-B", "s__u--b"},   // long s (EqualFold), delimiters (json/v2)
		{"iss", "ISS", "\u0131ss", "\u0130SS", "i\u00df", "I\u1e9e", "i-s-s"},       // dotless and dotted i, sharp s
		{"nickname", "NICKNAME", "nic\u212aname"},                                   // Kelvin sign
		{"profile", "PROFILE", "pro\ufb01le"},                                       // fi ligature
		{"address", "ADDRESS", "addre\u00df"},                                       // sharp s
		{"email_verified", "EmailVerified", "email-verified", "email_veri\ufb01ed"}, // delimiters, fi ligature
		{"office", "o\ufb03ce", "O\ufb00ICE"},                                       // ffi, ff ligatures
		{"waffle", "wa\ufb04e"},                                                     // ffl ligature
		{"flow", "\ufb02ow"},                                                        // fl ligature
		{"stable", "\ufb06able", "\ufb05able"},                                      // st, long s t ligatures
		{"name#fr", "NAME#FR", "name#Fr", "na_me#fr"},                               // language tags
		{"a\xff", "a\xfe", "a\ufffd"},                                               // invalid UTF-8: U+FFFD
	}

	for _, group := range same {
		for _, name := range group[1:] {
			assert.Equal(t, claimKey(group[0]), claimKey(name), "%q and %q", group[0], name)
		}
	}

	different := [][2]string{
		{"sub", "subs"}, {"email", "e.mail"}, {"name#fr", "name#de"}, {"name", "name#"},
		{"s", "\u00df"}, {"name", "n\u00e1me"}, {"st", "st\u0301"},
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
