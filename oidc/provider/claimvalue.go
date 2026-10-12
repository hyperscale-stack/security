// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxClaimDepth bounds the nesting of a released claim value: the claims
// object is one level, and strict relying parties — oidc/client among
// them — refuse a document nested deeper than 32.
const maxClaimDepth = 31

// wellFormedValue reports whether an encoded claim value can be released:
// valid UTF-8 without an unpaired surrogate escape, nested at most
// maxClaimDepth levels, without an object holding a member name with
// U+FFFD — what encoding/json writes for invalid UTF-8 — or a control
// character, or two member names that are case variants of each other,
// exact duplicates included, nor a number beyond float64. A relying party
// decoding such a value with encoding/json reads members under names they
// never had — or, decoding the claims into an any, refuses the whole
// document for such a number — and a strict one, oidc/client, refuses the
// whole token.
func wellFormedValue(encoded []byte) bool {
	if !utf8.Valid(encoded) || !pairedSurrogates(encoded) {
		return false
	}

	dec := json.NewDecoder(bytes.NewReader(encoded))
	dec.UseNumber()

	return wellFormedNext(dec, 0)
}

// wellFormedNext reads the next value of dec, nested depth levels deep.
func wellFormedNext(dec *json.Decoder, depth int) bool {
	tok, err := dec.Token()
	if err != nil {
		return false
	}

	delim, ok := tok.(json.Delim)
	if !ok {
		return finiteNumber(tok)
	}

	if depth == maxClaimDepth {
		return false
	}

	names := map[string]struct{}{}

	for dec.More() {
		if delim == '{' && !uniqueMember(dec, names) {
			return false
		}

		if !wellFormedNext(dec, depth+1) {
			return false
		}
	}

	_, err = dec.Token() // the closing delimiter

	return err == nil
}

// finiteNumber reports whether a scalar token is no number beyond float64:
// strconv.ParseFloat answers those with ErrRange, as encoding/json refuses
// them when it decodes into a float64 or an any.
func finiteNumber(tok json.Token) bool {
	n, ok := tok.(json.Number)
	if !ok {
		return true
	}

	_, err := strconv.ParseFloat(n.String(), 64)

	return err == nil
}

// uniqueMember reads a member name of an object, and reports whether it is
// valid UTF-8 without control characters and no case variant of a name
// already in names, which gets it.
func uniqueMember(dec *json.Decoder, names map[string]struct{}) bool {
	tok, err := dec.Token()
	name, _ := tok.(string)

	if err != nil || strings.ContainsRune(name, utf8.RuneError) || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return false
	}

	key := claimKey(name)
	if _, dup := names[key]; dup {
		return false
	}

	names[key] = struct{}{}

	return true
}

// pairedSurrogates reports whether every \u escape of a UTF-16 surrogate in
// the JSON text data is half of a high-low pair — as oidc/client requires:
// encoding/json turns every other one into U+FFFD, mapping distinct inputs
// to one value. Escapes are only looked for inside strings.
func pairedSurrogates(data []byte) bool {
	inString := false

	for i := 0; i < len(data); i++ {
		c := data[i]

		if !inString {
			inString = c == '"'

			continue
		}

		switch {
		case c == '"':
			inString = false
		case c != '\\' || i+1 >= len(data):
		case data[i+1] != 'u':
			i++ // an escaped character, such as \" or \\
		default:
			next, ok := surrogateEscape(data, i)
			if !ok {
				return false
			}

			i = next
		}
	}

	return true
}

// surrogateEscape checks the \u escape at data[i] and returns the index of
// its last byte — of the low half, for a surrogate pair — or false for an
// unpaired surrogate.
func surrogateEscape(data []byte, i int) (int, bool) {
	r, ok := hex4(data, i+2)

	switch {
	case !ok:
		return i + 1, true // not an escape encoding/json writes; it validated the text
	case r >= 0xDC00 && r <= 0xDFFF:
		return 0, false // a low half first
	case r < 0xD800 || r > 0xDBFF:
		return i + 5, true // no surrogate
	}

	if i+7 < len(data) && data[i+6] == '\\' && data[i+7] == 'u' {
		if low, ok := hex4(data, i+8); ok && low >= 0xDC00 && low <= 0xDFFF {
			return i + 11, true
		}
	}

	return 0, false // a high half alone
}

// hex4 parses the four hexadecimal digits at data[at:at+4].
func hex4(data []byte, at int) (rune, bool) {
	if at+4 > len(data) {
		return 0, false
	}

	v, err := strconv.ParseUint(string(data[at:at+4]), 16, 16)
	if err != nil {
		return 0, false
	}

	return rune(v), true
}
