// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec

import (
	"strings"
	"testing"

	josejson "github.com/go-jose/go-jose/v4/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateJSON(t *testing.T) {
	t.Parallel()

	nest := func(depth int) string {
		return `{"a":` + strings.Repeat("[", depth-1) + strings.Repeat("]", depth-1) + `}`
	}

	valid := map[string]string{
		"simple":                   `{"sub":"a","n":1,"b":true,"x":null,"arr":[1,"two",{"k":"v"}]}`,
		"distinct names":           `{"sub":"a","sid":"b","s":"c"}`,
		"same name, other objects": `{"a":{"x":1},"b":{"x":2},"c":[{"x":1},{"x":2}]}`,
		"surrogate pair":           `{"e":"` + esc("d83d") + esc("de00") + `"}`,
		"raw non-BMP character":    `{"e":"😀"}`,
		"escaped backslash u":      `{"e":"\\ud800"}`,
		"escaped quote":            `{"e":"a\"b\\"}`,
		"unicode escape":           `{"e":"` + esc("00e9") + `"}`,
		"raw non-ASCII":            `{"e":"é"}`,
		"max depth":                nest(maxJSONDepth),
		"whitespace":               " \n{ \"a\" : 1 }\n ",
		"empty object":             `{}`,
		"deep objects":             strings.Repeat(`{"a":`, maxJSONDepth) + `1` + strings.Repeat(`}`, maxJSONDepth),
	}

	for name, doc := range valid {
		t.Run("valid "+name, func(t *testing.T) {
			t.Parallel()
			require.NoError(t, validateJSON([]byte(doc)))
		})
	}

	invalid := map[string]string{
		"exact duplicate":           `{"sub":"a","sub":"b"}`,
		"escaped duplicate":         `{"sub":"a","s` + esc("0075") + `b":"b"}`,
		"case variant":              `{"sub":"a","SUB":"b"}`,
		"kelvin sign":               `{"kid":"a","` + esc("212a") + `id":"b"}`,
		"raw kelvin sign":           `{"kid":"a","Kid":"b"}`,
		"long s":                    `{"sub":"a","` + esc("017f") + `ub":"b"}`,
		"raw long s":                `{"sub":"a","ſub":"b"}`,
		"nested duplicate":          `{"a":{"x":1,"x":2}}`,
		"duplicate in array object": `{"a":[1,{"x":1,"X":2}]}`,
		"lone high surrogate":       `{"e":"` + esc("d800") + `"}`,
		"lone low surrogate":        `{"e":"` + esc("dc00") + `"}`,
		"high then non-surrogate":   `{"e":"` + esc("d800") + esc("0041") + `"}`,
		"high then text":            `{"e":"` + esc("d800") + `abcdef"}`,
		"surrogate in a name":       `{"` + esc("d800") + `":1}`,
		"invalid UTF-8":             "{\"e\":\"\xff\"}",
		"overlong UTF-8":            "{\"e\":\"\xc0\xaf\"}",
		"trailing object":           `{"a":1}{"b":2}`,
		"trailing garbage":          `{"a":1} x`,
		"array":                     `[{"a":1}]`,
		"string":                    `"a"`,
		"number":                    `1`,
		"null":                      `null`,
		"empty":                     ``,
		"truncated":                 `{"a":`,
		"too deep":                  nest(maxJSONDepth + 1),
		"unquoted name":             `{a:1}`,
		"leading comma":             `{,}`,
		"unclosed object":           `{"a":1`,
		"unclosed array":            `{"a":[1`,
		"too deep objects":          strings.Repeat(`{"a":`, maxJSONDepth+1) + `1` + strings.Repeat(`}`, maxJSONDepth+1),
	}

	for name, doc := range invalid {
		t.Run("invalid "+name, func(t *testing.T) {
			t.Parallel()
			require.ErrorIs(t, validateJSON([]byte(doc)), errJSON)
		})
	}
}

func TestFoldKey(t *testing.T) {
	t.Parallel()

	pairs := [][2]string{
		{"sub", "SUB"},
		{"kid", "Kid"}, // KELVIN SIGN folds to k
		{"sub", "ſub"}, // LATIN SMALL LETTER LONG S folds to s
		{"Straße", "straße"},
		{"σ", "Σ"},
		{"ς", "Σ"}, // final sigma shares the orbit
	}

	for _, p := range pairs {
		assert.Equal(t, foldKey(p[0]), foldKey(p[1]), "%q vs %q", p[0], p[1])
		assert.True(t, strings.EqualFold(p[0], p[1]), "the fold key agrees with strings.EqualFold for %q/%q", p[0], p[1])
	}

	assert.NotEqual(t, foldKey("sub"), foldKey("sid"))
	assert.NotEqual(t, foldKey("ss"), foldKey("ß"), "simple folding: ß is not ss")
}

func TestCheckSurrogatesMalformedInput(t *testing.T) {
	t.Parallel()

	// The scan runs before the decoder validates the document: it must never
	// panic on truncated escapes, and leaves them to the decoder.
	for _, doc := range []string{`"\u`, `"\ud8`, `"\ud800\u`, `"\ud800\udc`, `"\`, `"\uzzzz"`} {
		assert.NotPanics(t, func() { _ = checkSurrogates([]byte(doc)) }, doc)
	}
}

// panicky panics when decoded: decodeStrict must turn a decoder panic into
// an error rather than crash the caller.
type panicky struct{}

func (*panicky) UnmarshalJSON([]byte) error { panic("boom") }

func TestDecodeStrict(t *testing.T) {
	t.Parallel()

	var m map[string]any

	require.NoError(t, decodeStrict([]byte(`{"a":{"b":[1]}}`), &m))
	assert.Equal(t, map[string]any{"a": map[string]any{"b": []any{float64(1)}}}, m)

	require.ErrorIs(t, decodeStrict([]byte(`{"a":1,"A":2}`), &m), errJSON, "validated first")
	require.ErrorIs(t, decodeStrict([]byte(`{"a":"x"}`), &struct {
		A int `json:"a"`
	}{}), errJSON, "type errors are errJSON")

	var p struct {
		P *panicky `json:"p"`
	}

	require.NotPanics(t, func() {
		require.ErrorIs(t, decodeStrict([]byte(`{"p":{}}`), &p), errJSON)
	})
}

// FuzzStrictJSON checks that validateJSON never panics and that every
// document it accepts is one object go-jose's exact decoder reads, with
// no two top-level names equal under case folding.
func FuzzStrictJSON(f *testing.F) {
	for _, seed := range []string{
		`{"sub":"a","SUB":"b"}`, `{"a":{"b":[1,{"c":null}]}}`, `{"e":"\ud800"}`, "{\"e\":\"\xff\"}",
		`{"a":1} x`, `[]`, `{"ſub":1,"sub":2}`, `{"s` + esc("0075") + `b":1,"sub":2}`, `{"e":"` + esc("dc00") + `"}`,
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if validateJSON(data) != nil {
			return
		}

		var members map[string]josejson.RawMessage
		require.NoError(t, josejson.Unmarshal(data, &members), "an accepted document decodes")

		seen := map[string]bool{}

		for name := range members {
			key := foldKey(name)
			require.False(t, seen[key], "fold collision accepted: %q", data)

			seen[key] = true
		}
	})
}

// esc returns the JSON escape of the UTF-16 code unit hex (RFC 8259 §7).
// Built at run time so that the test sources hold no escape sequence a
// tool could normalise into the character itself.
func esc(hex string) string { return `\` + "u" + hex }

func TestClaimTypeHelpers(t *testing.T) {
	t.Parallel()

	assert.Equal(t, byte(0), jsonKind(nil), "an empty value has no kind")
	assert.Equal(t, byte(0), jsonKind([]byte("  ")))
	assert.Equal(t, byte('"'), jsonKind([]byte(` "a"`)))
	assert.True(t, isAudience([]byte(` "a"`)))
	assert.True(t, isAudience([]byte(`["a","b"]`)))
	assert.False(t, isAudience([]byte(`[1`)), "a malformed array is no audience")
	assert.False(t, isAudience([]byte(`["a",1]`)))
	assert.False(t, isJSONNumber([]byte(`null`)))
	assert.True(t, isJSONNumber([]byte(`-1.5e3`)))
}
