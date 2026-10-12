// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient

import (
	"strings"
	"testing"

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
		"surrogate pair":           `{"e":"\ud83d\ude00"}`,
		"escaped backslash u":      `{"e":"\\ud800"}`,
		"escaped quote":            `{"e":"a\"b\\"}`,
		"unicode escape":           `{"e":"\u00e9"}`,
		"max depth":                nest(32),
		"whitespace":               " \n{ \"a\" : 1 }\n ",
		"empty object":             `{}`,
		"deep objects":             strings.Repeat(`{"a":`, 32) + `1` + strings.Repeat(`}`, 32),
	}

	for name, doc := range valid {
		t.Run("valid "+name, func(t *testing.T) {
			t.Parallel()
			require.NoError(t, validateJSON([]byte(doc)))
		})
	}

	invalid := map[string]string{
		"exact duplicate":           `{"sub":"a","sub":"b"}`,
		"escaped duplicate":         `{"sub":"a","s\u0075b":"b"}`,
		"case variant":              `{"sub":"a","SUB":"b"}`,
		"kelvin sign":               `{"kid":"a","\u212aid":"b"}`,
		"long s":                    `{"sub":"a","\u017fub":"b"}`,
		"nested duplicate":          `{"a":{"x":1,"x":2}}`,
		"duplicate in array object": `{"a":[1,{"x":1,"X":2}]}`,
		"lone high surrogate":       `{"e":"\ud800"}`,
		"lone low surrogate":        `{"e":"\udc00"}`,
		"high then non-surrogate":   `{"e":"\ud800\u0041"}`,
		"high then text":            `{"e":"\ud800abcdef"}`,
		"surrogate in a name":       `{"\ud800":1}`,
		"invalid UTF-8":             "{\"e\":\"\xff\"}",
		"overlong UTF-8":            "{\"e\":\"\xc0\xaf\"}",
		"trailing object":           `{"a":1}{"b":2}`,
		"trailing garbage":          `{"a":1} x`,
		"array":                     `[{"a":1}]`,
		"string":                    `"a"`,
		"number":                    `1`,
		"empty":                     ``,
		"truncated":                 `{"a":`,
		"too deep":                  nest(33),
		"unquoted name":             `{a:1}`,
		"leading comma":             `{,}`,
		"unclosed object":           `{"a":1`,
		"unclosed array":            `{"a":[1`,
		"too deep objects":          strings.Repeat(`{"a":`, 33) + `1` + strings.Repeat(`}`, 33),
	}

	for name, doc := range invalid {
		t.Run("invalid "+name, func(t *testing.T) {
			t.Parallel()
			require.Error(t, validateJSON([]byte(doc)))
		})
	}
}

func TestFoldKey(t *testing.T) {
	t.Parallel()

	pairs := [][2]string{
		{"sub", "SUB"},
		{"kid", "\u212aid"}, // KELVIN SIGN folds to k
		{"sub", "\u017fub"}, // LATIN SMALL LETTER LONG S folds to s
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

	// The scan runs on documents the decoder then validates; it must never
	// panic on truncated escapes.
	for _, doc := range []string{`"\u`, `"\ud8`, `"\ud800\u`, `"\ud800\udc`, `"\`, `"\uzzzz"`} {
		assert.NotPanics(t, func() { _ = checkSurrogates([]byte(doc)) }, doc)
	}
}
