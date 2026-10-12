// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	josejson "github.com/go-jose/go-jose/v4/json"
)

// maxJSONDepth bounds the nesting of the JSON documents the package reads.
const maxJSONDepth = 32

// errJSON reports a document refused by validateJSON or decodeStrict; the
// callers wrap it with the sentinel of the document's role.
var errJSON = errors.New("malformed JSON document")

// decodeStrict validates data with validateJSON, then decodes it into v
// with exact (case-sensitive) member matching — OpenID Connect Core §14 and
// Discovery §5 compare names code point by code point, while encoding/json
// matches struct fields case-insensitively.
func decodeStrict(data []byte, v any) error {
	if err := validateJSON(data); err != nil {
		return err
	}

	if err := josejson.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%w: %w", errJSON, err)
	}

	return nil
}

// validateJSON accepts exactly one JSON object of valid UTF-8 (RFC 8725
// §3.7) without unpaired surrogate escapes, nested at most maxJSONDepth
// levels, in which no object — at any level — holds two member names that
// are equal under Unicode simple case folding (strings.EqualFold), exact
// duplicates included (RFC 7519 §4, RFC 7517 §5). A member name an
// application decodes with encoding/json can therefore never resolve to
// another member than the one the package validated.
func validateJSON(data []byte) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("%w: invalid UTF-8", errJSON)
	}

	if err := checkSurrogates(data); err != nil {
		return err
	}

	dec := json.NewDecoder(bytes.NewReader(data))

	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("%w: %w", errJSON, err)
	}

	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return fmt.Errorf("%w: not a JSON object", errJSON)
	}

	if err := walkObject(dec, 1); err != nil {
		return err
	}

	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: data after the object", errJSON)
	}

	return nil
}

// walkObject consumes the members of an object whose '{' was read.
func walkObject(dec *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return fmt.Errorf("%w: nested deeper than %d", errJSON, maxJSONDepth)
	}

	names := map[string]struct{}{}

	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("%w: %w", errJSON, err)
		}

		key := foldKey(tok.(string)) //nolint:forcetypeassert // dec.More inside an object yields a member name

		if _, dup := names[key]; dup {
			return fmt.Errorf("%w: duplicate or case-variant member name", errJSON)
		}

		names[key] = struct{}{}

		if err := walkValue(dec, depth); err != nil {
			return err
		}
	}

	return closeDelim(dec)
}

// walkArray consumes the elements of an array whose '[' was read.
func walkArray(dec *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return fmt.Errorf("%w: nested deeper than %d", errJSON, maxJSONDepth)
	}

	for dec.More() {
		if err := walkValue(dec, depth); err != nil {
			return err
		}
	}

	return closeDelim(dec)
}

// walkValue consumes one value of a container at depth.
func walkValue(dec *json.Decoder, depth int) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("%w: %w", errJSON, err)
	}

	switch tok {
	case json.Delim('{'):
		return walkObject(dec, depth+1)
	case json.Delim('['):
		return walkArray(dec, depth+1)
	}

	return nil
}

// closeDelim consumes the '}' or ']' closing a container.
func closeDelim(dec *json.Decoder) error {
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("%w: %w", errJSON, err)
	}

	return nil
}

// foldKey maps s to a canonical form such that foldKey(a) == foldKey(b)
// exactly when strings.EqualFold(a, b): every rune becomes the smallest
// rune of its Unicode simple case-folding orbit.
func foldKey(s string) string {
	var b strings.Builder

	b.Grow(len(s))

	for _, r := range s {
		smallest := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			smallest = min(smallest, f)
		}

		b.WriteRune(smallest)
	}

	return b.String()
}

// checkSurrogates refuses a \u escape of a UTF-16 surrogate that is not
// part of a high-low pair: encoding/json would turn every such escape into
// U+FFFD, mapping distinct inputs to one value. It reads only escapes inside
// strings; malformed escapes are left for the decoder to refuse.
func checkSurrogates(data []byte) error {
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
			i++ // skip the escaped character, such as \" or \\
		default:
			next, err := surrogateEscape(data, i)
			if err != nil {
				return err
			}

			i = next
		}
	}

	return nil
}

// surrogateEscape checks the \u escape at data[i] and returns the index of
// its last byte (of the low half, for a surrogate pair).
func surrogateEscape(data []byte, i int) (int, error) {
	r, ok := hex4(data, i+2)

	switch {
	case !ok:
		return i + 1, nil // malformed: the decoder refuses it
	case r >= 0xDC00 && r <= 0xDFFF:
		return 0, fmt.Errorf("%w: unpaired low surrogate escape", errJSON)
	case r < 0xD800 || r > 0xDBFF:
		return i + 5, nil
	}

	if i+7 < len(data) && data[i+6] == '\\' && data[i+7] == 'u' {
		if low, ok := hex4(data, i+8); ok && low >= 0xDC00 && low <= 0xDFFF {
			return i + 11, nil
		}
	}

	return 0, fmt.Errorf("%w: unpaired high surrogate escape", errJSON)
}

// hex4 parses the four hex digits at data[at:at+4].
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
