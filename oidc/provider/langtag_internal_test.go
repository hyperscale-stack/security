// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLanguageTag pins RFC 5646 \u00a72.1 well-formedness (\u00a72.2.9: the ABNF,
// not the registry): the examples of Appendix A, every production's
// bounds, and the irregular grandfathered tags, compared case-insensitively
// (\u00a72.1.1).
func TestLanguageTag(t *testing.T) {
	t.Parallel()

	wellFormed := []string{
		// Appendix A.
		"de", "fr", "ja", "i-enochian", "zh-Hant", "zh-Hans", "sr-Cyrl", "sr-Latn", "zh-cmn-Hans-CN", "cmn-Hans-CN",
		"zh-yue-HK", "yue-HK", "zh-Hans-CN", "sr-Latn-RS", "sl-rozaj", "sl-rozaj-biske", "sl-nedis", "de-CH-1901",
		"sl-IT-nedis", "hy-Latn-IT-arevela", "de-DE", "en-US", "es-419", "de-CH-x-phonebk", "az-Arab-x-AZE-derbend",
		"x-whatever", "qaa-Qaaa-QM-x-southern", "de-Qaaa", "sr-Latn-QM", "sr-Qaaa-RS", "en-US-u-islamcal",
		"zh-CN-a-myext-x-private", "en-a-myext-b-another",
		// Repeated singletons are well formed, though not valid (\u00a72.2.6, \u00a72.2.9).
		"ar-a-aaa-b-bbb-a-ccc",
		// Language: 2*3ALPHA [extlang] / 4ALPHA / 5*8ALPHA.
		"abc", "abcd", "abcde", "abcdefgh", "verified", "zh-abc-def-ghi",
		// Script, region (2ALPHA / 3DIGIT), variants (5*8alphanum / DIGIT 3alphanum).
		"en-Latn", "en-GB", "en-123", "en-1234", "de-1996", "en-abcde", "en-12345678", "en-1abc", "en-Latn-GB-1abc-abcde",
		// Extensions: any singleton but x \u2014 i and digits included \u2014 then 2 to 8 alphanum.
		"en-i-abc", "de-1-abc", "en-a-ab", "en-a-abcdefgh", "en-a-ab-cd-x-y",
		// Private use: 1 to 8 alphanum after x.
		"en-x-a", "x-a", "x-abcdefgh", "X-ABC", "x-a-b-c",
		// Irregular grandfathered tags, any case; the regular ones match langtag.
		"en-GB-oed", "EN-gb-OED", "i-ami", "i-bnn", "i-default", "i-hak", "i-klingon", "I-KLINGON", "i-lux", "i-mingo",
		"i-navajo", "i-pwn", "i-tao", "i-tay", "i-tsu", "sgn-BE-FR", "sgn-BE-NL", "sgn-CH-DE",
		"art-lojban", "cel-gaulish", "no-bok", "no-nyn", "zh-guoyu", "zh-hakka", "zh-min", "zh-min-nan", "zh-xiang",
		// Case is not significant (\u00a72.1.1).
		"FR", "Fr-ca", "ZH-HANT-tw", "SR-latn-rs",
	}

	for _, tag := range wellFormed {
		assert.True(t, languageTag(tag), "%q is well formed", tag)
	}

	malformed := []string{
		"", "-", "fr-", "-fr", "fr--CA", "fr-CA-",
		// Appendix A's malformed examples.
		"de-419-DE", "a-DE",
		// Language.
		"a", "1", "12", "a1", "abcdefghi", "toolongtag", "fr1",
		// Extlang only after a 2*3ALPHA language, at most three.
		"abcd-efg", "abcde-fgh", "zh-abc-def-ghi-jkl",
		// Region 3DIGIT vs variant DIGIT 3alphanum; a script is 4ALPHA, a
		// variant of 4 starts with a digit, and neither comes back.
		"en-12", "en-1a", "en-1abc-GB", "en-Latn-abcd", "en-GB-abcd", "en-Latn-Cyrl", "en-GB-US",
		// Subtags of at most 8.
		"fr-abcdefghi", "en-a-abcdefghi", "x-abcdefghi",
		// Extensions and private use need a subtag.
		"en-a", "en-a-b", "en-a-x-y", "x", "x-", "en-x", "en-x-",
		// A grandfathered prefix is no tag.
		"i", "i-unknown", "i-klingon-x", "en-GB-oed-x-y",
		// Characters outside ASCII letters, digits and "-".
		"fr_CA", "fr CA", "fr.CA", "fr-CA#x", "fr-\u00c7a", "\u0131-klingon", "fr-\u212aA",
		"i-\u212alingon", "\u017fgn-BE-FR", // EqualFold would equate them with i-klingon and sgn-BE-FR
	}

	for _, tag := range malformed {
		assert.False(t, languageTag(tag), "%q is not well formed", tag)
	}
}

// TestSplitTag: a claim name is language-tagged (OIDC Core \u00a75.2) when a
// claim name and a well-formed language tag surround its first "#"; any
// other "#" is an ordinary character (RFC 7519 \u00a74.2 URI names).
func TestSplitTag(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, base string
		tagged     bool
	}{
		{"name#fr", "name", true},
		{"family_name#ja-Kana-JP", "family_name", true},
		{"email#verified", "email", true},
		{"name#x-private", "name", true},
		{"name#i-klingon", "name", true},
		{"https://example.com/claims#roles", "https://example.com/claims", true},
		{"name", "name", false},
		{"name#", "name#", false},
		{"name#-", "name#-", false},
		{"name#fr-", "name#fr-", false},
		{"name#fr#de", "name#fr#de", false},
		{"#fr", "#fr", false},
		{"#", "#", false},
		{"https://example.com/claims#user_roles", "https://example.com/claims#user_roles", false},
	}

	for _, tc := range cases {
		base, tag, tagged := splitTag(tc.name)
		assert.Equal(t, tc.base, base, "%q", tc.name)
		assert.Equal(t, tc.tagged, tagged, "%q", tc.name)
		assert.Equal(t, tc.base, untagged(tc.name), "%q", tc.name)

		if tagged {
			assert.Equal(t, tc.name, base+"#"+tag, "%q", tc.name)
		} else {
			assert.Empty(t, tag, "%q", tc.name)
		}
	}
}

// FuzzLanguageTag: languageTag never panics, accepts only ASCII subtags of
// 1 to 8 letters or digits separated by single hyphens, and ignores case.
func FuzzLanguageTag(f *testing.F) {
	for _, seed := range []string{"fr", "zh-cmn-Hans-CN", "x-whatever", "i-klingon", "en-a-ab-x-y", "de-419-DE", "", "-", "\u212a"} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, tag string) {
		ok := languageTag(tag)

		if !isASCII(tag) {
			require.False(t, ok, "%q: not ASCII", tag)

			return
		}

		require.Equal(t, ok, languageTag(strings.ToUpper(tag)), "%q: case changes the verdict", tag)
		require.Equal(t, ok, languageTag(strings.ToLower(tag)), "%q: case changes the verdict", tag)

		if !ok {
			return
		}

		for subtag := range strings.SplitSeq(tag, "-") {
			require.True(t, len(subtag) >= 1 && len(subtag) <= 8, "%q: subtag %q", tag, subtag)

			for i := range len(subtag) {
				c := subtag[i]
				require.True(t, 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9', "%q: byte %q", tag, c)
			}
		}
	})
}

// isASCII reports whether s holds ASCII only.
func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= 0x80 {
			return false
		}
	}

	return true
}

// FuzzSplitTagKey: a tagged name is its base, "#" and a well-formed tag;
// the base is not empty and holds no "#"; and the key of the name is the
// key of the base followed by the key of the tag \u2014 the key ignores "#", as
// lodash's and change-case's camelCase do.
func FuzzSplitTagKey(f *testing.F) {
	for _, seed := range []string{"name#fr", "email#verified-fr", "#fr", "name#", "\u00e9mail#fr", "a#b#c", "https://e.example/c#roles"} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, name string) {
		base, tag, tagged := splitTag(name)
		if !tagged {
			require.Equal(t, name, base)
			require.Empty(t, tag)

			return
		}

		require.Equal(t, name, base+"#"+tag)
		require.NotEmpty(t, base)
		require.NotContains(t, base, "#")
		require.True(t, languageTag(tag))
		require.Equal(t, claimKey(name), claimKey(base)+claimKey(tag), "%q", name)
	})
}
