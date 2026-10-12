// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestPairedSurrogates pins the surrogate scan of released values: an
// escaped surrogate must be half of a high-low pair; a malformed escape is
// left to the JSON decoder, and escapes are only read inside strings.
func TestPairedSurrogates(t *testing.T) {
	t.Parallel()

	cases := map[string]bool{
		`"\ud83d\ude00"`:   true,  // a pair
		`"\u00e9\u2028"`:   true,  // no surrogate
		`"\\ud800"`:        true,  // an escaped backslash, then text
		`"a\"\ud800"`:      false, // an escaped quote does not end the string
		`"\ud800"`:         false, // a high half alone
		`"\ud800\u0041"`:   false, // a high half before another escape
		`"\ud800x"`:        false, // a high half before text
		`"\udc00"`:         false, // a low half alone
		`["\ud800", 1]`:    false, // inside an array
		`{"\ud800": 1}`:    false, // in a member name
		`"\u12"`:           true,  // malformed: left to the decoder
		`"\uZZZZ"`:         true,  // malformed: left to the decoder
		`"\`:               true,  // truncated
		`1`:                true,  // no string
		`"ud800" "\ud800"`: false, // the second string
	}

	for doc, want := range cases {
		assert.Equal(t, want, pairedSurrogates([]byte(doc)), "%s", doc)
	}
}

// TestWellFormedValueRefusesMalformedJSON: the value check refuses what
// the JSON decoder refuses — encoding/json never writes it, but the check
// fails closed.
func TestWellFormedValueRefusesMalformedJSON(t *testing.T) {
	t.Parallel()

	for _, doc := range []string{`{"a":}`, `[1,`, `"\u12"`, `{"a" 1}`} {
		assert.False(t, wellFormedValue([]byte(doc)), "%s", doc)
	}

	assert.True(t, wellFormedValue([]byte(`{"a": [1, "two", {"b": null}]}`)))
}
