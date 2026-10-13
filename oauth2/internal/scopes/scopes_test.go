// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package scopes_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hyperscale-stack/security/oauth2/internal/scopes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParse pins the RFC 6749 §3.3 / Appendix A syntax: scope tokens are
// 1*NQCHAR (%x21 / %x23-5B / %x5D-7E), separated by SP only, compared
// case-sensitively. SP runs and leading or trailing SPs carry no token.
func TestParse(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"only spaces", "   ", nil},
		{"one token", "read", []string{"read"}},
		{"two tokens", "read write", []string{"read", "write"}},
		{"space runs and edges", "  read   write ", []string{"read", "write"}},
		{"duplicates dropped, first occurrence kept", "write read write read", []string{"write", "read"}},
		{"case-sensitive", "Read read", []string{"Read", "read"}},
		{"lowest NQCHAR", "!", []string{"!"}},
		{"right after the quote", "#", []string{"#"}},
		{"right before the backslash", "[", []string{"["}},
		{"right after the backslash", "]", []string{"]"}},
		{"highest NQCHAR", "~", []string{"~"}},
		{"URL-shaped", "https://www.googleapis.com/auth/drive.readonly openid", []string{
			"https://www.googleapis.com/auth/drive.readonly", "openid",
		}},
		{"URN-shaped", "urn:zitadel:iam:org:project:id:{id}:aud api://app/.default", []string{
			"urn:zitadel:iam:org:project:id:{id}:aud", "api://app/.default",
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := scopes.Parse(tc.in)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestParseRefusesWhatNQCHARExcludes: every byte outside NQCHAR is refused —
// the quote and the backslash, controls, DEL, any whitespace but SP as a
// separator, and every non-ASCII byte.
func TestParseRefusesWhatNQCHARExcludes(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"quote":            `a"b`,
		"backslash":        `a\b`,
		"DEL":              "a\x7fb",
		"NUL":              "a\x00b",
		"control":          "a\x01b",
		"tab as separator": "read\twrite",
		"line feed":        "read\nwrite",
		"carriage return":  "read\rwrite",
		"no-break space":   "read write",
		"line separator":   "read write",
		"non-ASCII token":  "lecture:é",
		"high byte":        "read\xffwrite",
	}

	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := scopes.Parse(in)
			require.ErrorIs(t, err, scopes.ErrMalformed)
			assert.Nil(t, got)
		})
	}
}

// tokens returns n distinct scope tokens joined by SP.
func tokens(n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = fmt.Sprintf("s%d", i)
	}

	return strings.Join(parts, " ")
}

// TestParseBounds pins the bounds: at most MaxLength bytes — refused before
// the value is read — and at most MaxTokens tokens, repetitions included.
func TestParseBounds(t *testing.T) {
	t.Parallel()

	longest := strings.Repeat("a", scopes.MaxLength)

	got, err := scopes.Parse(longest)
	require.NoError(t, err)
	assert.Equal(t, []string{longest}, got)

	_, err = scopes.Parse(longest + "a")
	require.ErrorIs(t, err, scopes.ErrTooLarge)

	// The length is judged first: a malformed value over the bound reports
	// its size.
	_, err = scopes.Parse(longest + "\t")
	require.ErrorIs(t, err, scopes.ErrTooLarge)

	got, err = scopes.Parse(tokens(scopes.MaxTokens))
	require.NoError(t, err)
	assert.Len(t, got, scopes.MaxTokens)

	_, err = scopes.Parse(tokens(scopes.MaxTokens + 1))
	require.ErrorIs(t, err, scopes.ErrTooLarge)

	_, err = scopes.Parse(strings.TrimSpace(strings.Repeat("a ", scopes.MaxTokens+1)))
	require.ErrorIs(t, err, scopes.ErrTooLarge, "repetitions count")

	got, err = scopes.Parse(strings.TrimSpace(strings.Repeat("a ", scopes.MaxTokens)))
	require.NoError(t, err)
	assert.Equal(t, []string{"a"}, got)
}

func TestSetAdmits(t *testing.T) {
	t.Parallel()

	set := scopes.NewSet([]string{"read", "write"})

	assert.True(t, set.Admits(nil), "any set admits no token")
	assert.True(t, set.Admits([]string{"read"}))
	assert.True(t, set.Admits([]string{"write", "read"}))
	assert.False(t, set.Admits([]string{"read", "admin"}))
	assert.False(t, set.Admits([]string{"Read"}), "case-sensitive")

	empty := scopes.NewSet(nil)
	assert.False(t, empty.Admits([]string{"read"}), "an empty set admits no token")
	assert.True(t, empty.Admits(nil))
}

func TestJoin(t *testing.T) {
	t.Parallel()

	assert.Empty(t, scopes.Join(nil))
	assert.Equal(t, "read", scopes.Join([]string{"read"}))
	assert.Equal(t, "write read", scopes.Join([]string{"write", "read"}))
}

// BenchmarkParse measures the largest value accepted.
func BenchmarkParse(b *testing.B) {
	value := tokens(scopes.MaxTokens)

	for b.Loop() {
		if _, err := scopes.Parse(value); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAdmits checks the largest request against a large registration:
// map lookups keep it linear in the request.
func BenchmarkAdmits(b *testing.B) {
	registered := make([]string, 10_000)
	for i := range registered {
		registered[i] = fmt.Sprintf("s%d", i)
	}

	set := scopes.NewSet(registered)
	requested, _ := scopes.Parse(tokens(scopes.MaxTokens))

	for b.Loop() {
		if !set.Admits(requested) {
			b.Fatal("refused")
		}
	}
}
