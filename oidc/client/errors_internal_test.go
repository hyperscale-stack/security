// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClip checks the bound on echoed text: unchanged up to maxEchoLength
// bytes, then the first and last halves around "...", cut on rune
// boundaries, invalid UTF-8 replaced first.
func TestClip(t *testing.T) {
	t.Parallel()

	atBound := strings.Repeat("a", maxEchoLength)
	assert.Equal(t, atBound, clip(atBound), "at the bound: unchanged")
	assert.Equal(t, strings.Repeat("a", 128)+"..."+strings.Repeat("a", 128), clip(atBound+"a"), "one byte over: cut")

	headTail := strings.Repeat("h", 200) + strings.Repeat("m", 1_000) + strings.Repeat("t", 200)
	assert.Equal(t, strings.Repeat("h", 128)+"..."+strings.Repeat("t", 128), clip(headTail))

	// A 4-byte rune straddles each cut point: both cuts move to a rune
	// boundary, never through the rune.
	straddling := strings.Repeat("a", 127) + "😀" + strings.Repeat("m", 500) + "😀" + strings.Repeat("b", 126)
	got := clip(straddling)
	assert.True(t, utf8.ValidString(got))
	assert.Equal(t, strings.Repeat("a", 127)+"..."+strings.Repeat("b", 126), got)

	for name, s := range map[string]string{
		"invalid run":            strings.Repeat("\xff", 1_000),
		"interleaved invalid":    strings.Repeat("a\xff", 1_000),
		"truncated rune at ends": "\xe2\x82" + strings.Repeat("é", 400) + "\xe2",
	} {
		got := clip(s)
		assert.True(t, utf8.ValidString(got), name)
		assert.LessOrEqual(t, len(got), maxEchoLength+len("..."), name)
	}

	q := quoted(strings.Repeat("\x01", 1_000))
	assert.LessOrEqual(t, len(q), maxEchoLength+len("..."), "quoted, then cut: escaping cannot inflate it")
	assert.True(t, strings.HasPrefix(q, `"\x01`) && strings.HasSuffix(q, `\x01"`), q)
	assert.Equal(t, `"short"`, quoted("short"))
}

// TestClipped checks that clipped bounds an error's text without breaking
// its chain: errors.Is and errors.As reach the original.
func TestClipped(t *testing.T) {
	t.Parallel()

	require.NoError(t, clipped(nil))

	short := errors.New("short")
	assert.Same(t, short, clipped(short), "a short error is returned as it is")

	sentinel := errors.New("sentinel")
	long := clipped(fmt.Errorf("%w: %s", sentinel, strings.Repeat("x", 10_000)))
	require.ErrorIs(t, long, sentinel)
	assert.LessOrEqual(t, len(long.Error()), maxEchoLength+len("..."))
	assert.True(t, strings.HasPrefix(long.Error(), "sentinel: xxx"))

	redirect := clipped(&url.Error{Op: "Get", URL: "https://elsewhere.example/" + strings.Repeat("A", 10_000), Err: sentinel})

	var urlErr *url.Error
	require.ErrorAs(t, redirect, &urlErr)
	require.ErrorIs(t, redirect, sentinel)
	assert.True(t, strings.HasPrefix(redirect.Error(), `Get "https://elsewhere.example/AAA`), "the beginning names the operation")
	assert.True(t, strings.HasSuffix(redirect.Error(), `AAA": sentinel`), "the end keeps the cause")
}
