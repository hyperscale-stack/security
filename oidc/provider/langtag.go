// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider

import "strings"

// maxSubtagLength bounds a language subtag (RFC 5646 §2.1: "All subtags
// have a maximum length of eight characters").
const maxSubtagLength = 8

// irregularTags are the grandfathered tags of RFC 5646 §2.1 that do not
// match the langtag production (its "irregular" list); the "regular" ones
// do.
var irregularTags = []string{
	"en-GB-oed", "i-ami", "i-bnn", "i-default", "i-enochian", "i-hak", "i-klingon", "i-lux", "i-mingo",
	"i-navajo", "i-pwn", "i-tao", "i-tay", "i-tsu", "sgn-BE-FR", "sgn-BE-NL", "sgn-CH-DE",
}

// languageTag reports whether tag is a well-formed language tag — RFC 5646
// §2.1's Language-Tag production (langtag / privateuse / grandfathered),
// letters in any case (§2.1.1) — the conformance class of §2.2.9 that
// needs no registry: "valid" tags (registered subtags, singletons once
// each) are not required. OpenID Connect Core §5.2 delimits a claim's
// BCP 47 language tag with "#".
func languageTag(tag string) bool {
	subtags, ok := subtagsOf(tag)

	switch {
	case !ok:
		return false
	case irregular(tag):
		return true
	case isX(subtags[0]):
		return privateUse(subtags)
	default:
		return langtag(subtags)
	}
}

// subtagsOf splits tag at "-" into its subtags: false unless each is 1 to
// 8 ASCII letters or digits.
func subtagsOf(tag string) ([]string, bool) {
	subtags := strings.Split(tag, "-")

	for _, s := range subtags {
		if s == "" || len(s) > maxSubtagLength || !allOf(s, isAlphanum) {
			return nil, false
		}
	}

	return subtags, true
}

// irregular reports whether the ASCII tag is an irregular grandfathered
// tag. tag holds ASCII only (subtagsOf), so strings.EqualFold folds ASCII
// case only.
func irregular(tag string) bool {
	for _, t := range irregularTags {
		if strings.EqualFold(tag, t) {
			return true
		}
	}

	return false
}

// langtag reports whether subtags match RFC 5646's langtag: language
// ["-" script] ["-" region] *("-" variant) *("-" extension) ["-"
// privateuse]. Each production is told apart by its length and characters,
// so the subtags are read greedily.
func langtag(subtags []string) bool {
	i := languageEnd(subtags)
	if i == 0 {
		return false
	}

	if i < len(subtags) && isScript(subtags[i]) {
		i++
	}

	if i < len(subtags) && isRegion(subtags[i]) {
		i++
	}

	for i < len(subtags) && isVariant(subtags[i]) {
		i++
	}

	i, ok := extensionsEnd(subtags, i)

	switch {
	case !ok:
		return false
	case i < len(subtags) && isX(subtags[i]):
		return privateUse(subtags[i:])
	default:
		return i == len(subtags)
	}
}

// languageEnd returns the index of the subtag after the language —
// 2*3ALPHA ["-" extlang] / 4ALPHA / 5*8ALPHA, extlang = 3ALPHA *2("-"
// 3ALPHA) — or 0 when subtags start with no language.
func languageEnd(subtags []string) int {
	language := subtags[0]
	if len(language) < 2 || !allOf(language, isAlpha) {
		return 0
	}

	i := 1

	if len(language) <= 3 {
		for extlangs := 0; extlangs < 3 && i < len(subtags) && len(subtags[i]) == 3 && allOf(subtags[i], isAlpha); extlangs++ {
			i++
		}
	}

	return i
}

// extensionsEnd reads the extensions starting at subtags[i] — singleton
// 1*("-" (2*8alphanum)), any singleton but x — and returns the index after
// them; false for a singleton without a subtag.
func extensionsEnd(subtags []string, i int) (int, bool) {
	for i < len(subtags) && len(subtags[i]) == 1 && !isX(subtags[i]) {
		i++
		start := i

		for i < len(subtags) && len(subtags[i]) >= 2 {
			i++
		}

		if i == start {
			return 0, false
		}
	}

	return i, true
}

// privateUse reports whether subtags are a privateuse: "x" 1*("-"
// (1*8alphanum)) — subtags[0] being x and every subtag already 1 to 8
// alphanumerics.
func privateUse(subtags []string) bool {
	return len(subtags) >= 2
}

// isScript: script = 4ALPHA.
func isScript(s string) bool { return len(s) == 4 && allOf(s, isAlpha) }

// isRegion: region = 2ALPHA / 3DIGIT.
func isRegion(s string) bool {
	return len(s) == 2 && allOf(s, isAlpha) || len(s) == 3 && allOf(s, isDigit)
}

// isVariant: variant = 5*8alphanum / (DIGIT 3alphanum) — s holds
// alphanumerics only.
func isVariant(s string) bool {
	return len(s) >= 5 || len(s) == 4 && isDigit(s[0])
}

// isX reports the singleton x, which introduces a privateuse.
func isX(s string) bool { return s == "x" || s == "X" }

// allOf reports whether every byte of s satisfies class.
func allOf(s string, class func(byte) bool) bool {
	for i := range len(s) {
		if !class(s[i]) {
			return false
		}
	}

	return true
}

func isAlpha(c byte) bool { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }

func isDigit(c byte) bool { return '0' <= c && c <= '9' }

func isAlphanum(c byte) bool { return isAlpha(c) || isDigit(c) }
