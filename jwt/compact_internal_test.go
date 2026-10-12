// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec

import (
	"encoding/base64"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCanonicalBase64URL(t *testing.T) {
	t.Parallel()

	for s, want := range map[string]bool{
		"":      true,
		"A":     false, // 6 bits encode no octet
		"AA":    true,
		"AB":    false, // non-zero pad bits (4 unused)
		"AQ":    true,  // 0x01
		"AAA":   true,
		"AAB":   false, // non-zero pad bits (2 unused)
		"AAE":   true,
		"AAAA":  true,
		"AAAAA": false,
		"A-_z":  true,
		"AA==":  false,
		"A+/A":  false,
		"AA\n":  false,
		" AA":   false,
	} {
		assert.Equal(t, want, canonicalBase64URL(s), "%q", s)
	}

	// Every canonical encoding round-trips through the strict decoder.
	for n := range 8 {
		enc := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("\xff", n)))
		assert.True(t, canonicalBase64URL(enc), enc)
	}
}

func TestCheckCompact(t *testing.T) {
	t.Parallel()

	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`))
	p := base64.RawURLEncoding.EncodeToString([]byte(`{}`))

	require.NoError(t, checkCompact(h+"."+p+".AAAA", 1<<10))
	require.NoError(t, checkCompact(h+"."+p+".", 1<<10), "an empty signature is left to the verification")

	for name, tok := range map[string]string{
		"one segment":   h,
		"two segments":  h + "." + p,
		"four segments": h + "." + p + ".AAAA.AAAA",
		"empty header":  "." + p + ".AAAA",
		"empty payload": h + "..AAAA",
		"too long":      h + "." + p + "." + strings.Repeat("A", 1<<10),
	} {
		err := checkCompact(tok, 1<<10)
		require.ErrorIs(t, err, ErrMalformedToken, name)
	}
}

func TestClip(t *testing.T) {
	t.Parallel()

	exact := strings.Repeat("a", maxEchoedLength)
	assert.Equal(t, exact, clip(exact), "values up to the bound are kept")

	// "a" then two-byte runes: byte 128 is a continuation byte, so the cut
	// moves back to the start of that rune.
	got := clip("a" + strings.Repeat("\xc3\xa9", 100))
	assert.True(t, utf8.ValidString(got), "never cuts inside a rune")
	assert.True(t, strings.HasSuffix(got, "…"))
	assert.Equal(t, maxEchoedLength-1+len("…"), len(got))
}
