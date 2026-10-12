// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSAMLTime(t *testing.T) {
	t.Parallel()

	ok := map[string]time.Time{
		"2026-10-12T10:00:00Z":           time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC),
		"2026-10-12T10:00:00.5Z":         time.Date(2026, 10, 12, 10, 0, 0, 500000000, time.UTC),
		"2026-10-12T10:00:00.1234567Z":   time.Date(2026, 10, 12, 10, 0, 0, 123456700, time.UTC),
		"2026-10-12T10:00:00.123456789Z": time.Date(2026, 10, 12, 10, 0, 0, 123456789, time.UTC),
	}

	for in, want := range ok {
		got, err := parseSAMLTime(in)
		require.NoError(t, err, in)
		assert.True(t, got.Equal(want), in)
		assert.True(t, isSAMLTime(in), in)
	}

	bad := []string{
		"",
		"2026-10-12T10:00:00",             // no zone: ambiguous
		"2026-10-12T10:00:00+00:00",       // offset instead of Z (Core §1.3.3)
		"2026-10-12T10:00:00+02:00",       // offset
		"2026-10-12T10:00:00z",            // lowercase designator
		"2026-10-12 10:00:00Z",            // no T
		"2026/10/12T10:00:00Z",            // wrong separators
		"2026-10-12T10-00-00Z",            // wrong separators
		"2026-10-12T10:00:60Z",            // leap second (Core §1.3.3)
		"2026-13-12T10:00:00Z",            // month out of range
		"2026-10-12T10:00:00.Z",           // empty fraction
		"2026-10-12T10:00:00.1234567890Z", // fraction over 9 digits
		"2026-10-12T10:00:00.12a4Z",       // non-digit fraction
		"2026-10-12T10:00:00,5Z",          // comma fraction
		"+2026-10-12T10:00:00Z",
		"20261-10-12T10:00:00Z",
		"2026-1a-12T10:00:00Z",
	}

	for _, in := range bad {
		_, err := parseSAMLTime(in)
		require.ErrorIs(t, err, errBadTime, in)
	}
}

// formatSAMLTime renders t as a Core §1.3.3 time value (tests only).
func formatSAMLTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

func TestParseMetadataTime(t *testing.T) {
	t.Parallel()

	for in, want := range map[string]time.Time{
		"2026-10-12T10:00:00Z":      time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC),
		"2026-10-12T12:00:00+02:00": time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC),
		"2026-10-12T10:00:00":       time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC),
		"2026-10-12T10:00:00.25":    time.Date(2026, 10, 12, 10, 0, 0, 250000000, time.UTC),
	} {
		got, err := parseMetadataTime(in)
		require.NoError(t, err, in)
		assert.True(t, got.Equal(want), in)
	}

	_, err := parseMetadataTime("tomorrow")
	require.ErrorIs(t, err, errBadTime)
}

func TestParseXSDuration(t *testing.T) {
	t.Parallel()

	ok := map[string]time.Duration{
		"PT1H":         time.Hour,
		"PT86400S":     24 * time.Hour,
		"P1D":          24 * time.Hour,
		"P7D":          7 * 24 * time.Hour,
		"PT30M":        30 * time.Minute,
		"PT1.5S":       1500 * time.Millisecond,
		"P1DT2H3M4S":   26*time.Hour + 3*time.Minute + 4*time.Second,
		"P1Y":          365 * 24 * time.Hour,
		"P1M":          30 * 24 * time.Hour,
		"P1Y2M3DT4H":   (365+60+3)*24*time.Hour + 4*time.Hour,
		"PT0S":         0,
		"P0D":          0,
		"P1MT1M":       30*24*time.Hour + time.Minute,
		"PT1H30M0.25S": 90*time.Minute + 250*time.Millisecond,
	}

	for in, want := range ok {
		got, err := parseXSDuration(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}

	bad := []string{
		"", "P", "PT", "1H", "-PT1H", "PT1H2", "P1H", "PT1D", "PT1.5H", "P1.5D",
		"PT1S1M", "P1D1Y", "PT1HT1M", "P1DT", "PTH", "P.5D", "PT1..5S", "PT1M1M",
		"P99999999999999999999Y", "PTxS",
	}

	for _, in := range bad {
		_, err := parseXSDuration(in)
		require.ErrorIs(t, err, errBadDuration, in)
	}
}

// TestParseXSDurationOverflow pins the int64 bound: float64(math.MaxInt64)
// is exactly 2^63, so a total of 2^63 ns passes a ">" guard and its
// conversion to int64 is implementation-defined (MinInt64 on amd64,
// MaxInt64 on arm64). Such durations must be refused on every platform.
func TestParseXSDurationOverflow(t *testing.T) {
	t.Parallel()

	for _, in := range []string{
		"PT9223372036.854775808S",      // exactly 2^63 ns
		"PT9223372036.854775807S",      // 2^63 - 1 ns, rounded up to 2^63 by float64
		"P106751DT23H47M16.854775808S", // 2^63 ns spelled in days
		"PT2562047H47M16.854775808S",   // 2^63 ns spelled in hours
		"PT153722867M16.854775808S",    // 2^63 ns spelled in minutes
		"P106751DT23H47M16.854775809S", // above, rounded down to 2^63
		"PT9223372036.9S",              // above
		"PT9223372037S",                // above
		"P293Y",                        // above
	} {
		d, err := parseXSDuration(in)
		require.ErrorIs(t, err, errBadDuration, "%s parsed as %d", in, int64(d))
	}

	// The largest float64 below 2^63 ns still converts exactly.
	d, err := parseXSDuration("PT9223372036.854774S")
	require.NoError(t, err)
	assert.Equal(t, time.Duration(9223372036854774784), d)
}

func TestFormatXSDuration(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "PT86400S", formatXSDuration(24*time.Hour))
	assert.Equal(t, "PT60S", formatXSDuration(time.Minute+500*time.Millisecond))

	d, err := parseXSDuration(formatXSDuration(5 * time.Hour))
	require.NoError(t, err)
	assert.Equal(t, 5*time.Hour, d)
}
