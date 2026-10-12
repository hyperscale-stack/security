// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp

import (
	"errors"
	"math"
	"strconv"
	"time"
)

var (
	errBadTime     = errors.New("time value is not a UTC xs:dateTime")
	errBadDuration = errors.New("value is not a non-negative xs:duration")
)

// samlTimePattern is the fixed-width part of a Core §1.3.3 time value:
// 'd' stands for a decimal digit, any other byte must match itself.
const samlTimePattern = "dddd-dd-ddTdd:dd:dd"

// isSAMLTime reports whether s is an xs:dateTime in the UTC form Core §1.3.3
// requires: YYYY-MM-DDThh:mm:ss, an optional fraction, then "Z".
func isSAMLTime(s string) bool {
	if len(s) < len(samlTimePattern)+1 || s[len(s)-1] != 'Z' || !matchesDigits(s[:len(samlTimePattern)], samlTimePattern) {
		return false
	}

	frac := s[len(samlTimePattern) : len(s)-1]
	if frac == "" {
		return true
	}

	return len(frac) >= 2 && len(frac) <= 10 && frac[0] == '.' && allDigits(frac[1:])
}

// matchesDigits compares s with pattern ('d' = any decimal digit).
func matchesDigits(s, pattern string) bool {
	for i := 0; i < len(pattern); i++ {
		if pattern[i] == 'd' {
			if s[i] < '0' || s[i] > '9' {
				return false
			}

			continue
		}

		if s[i] != pattern[i] {
			return false
		}
	}

	return true
}

// allDigits reports whether s only holds decimal digits.
func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}

	return true
}

// parseSAMLTime parses a Core §1.3.3 time value (UTC, "Z").
func parseSAMLTime(s string) (time.Time, error) {
	if !isSAMLTime(s) {
		return time.Time{}, errBadTime
	}

	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, errBadTime
	}

	return t, nil
}

// parseMetadataTime parses a metadata validUntil: an xs:dateTime that may
// carry a time zone offset; a value without time zone is read as UTC.
func parseMetadataTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}

	t, err := time.Parse("2006-01-02T15:04:05.999999999", s)
	if err != nil {
		return time.Time{}, errBadTime
	}

	return t, nil
}

// formatXSDuration renders d (rounded down to seconds) as an xs:duration.
func formatXSDuration(d time.Duration) string {
	return "PT" + strconv.FormatInt(int64(d/time.Second), 10) + "S"
}

// durationUnit is one designator of an xs:duration.
type durationUnit struct {
	designator byte
	unit       time.Duration
	timePart   bool
}

// xsDurationUnits lists the designators in their mandatory order. Years and
// months have no fixed length: they are approximated as 365 and 30 days, a
// documented simplification that only affects cache-refresh hints.
var xsDurationUnits = []durationUnit{
	{'Y', 365 * 24 * time.Hour, false},
	{'M', 30 * 24 * time.Hour, false},
	{'D', 24 * time.Hour, false},
	{'H', time.Hour, true},
	{'M', time.Minute, true},
	{'S', time.Second, true},
}

// parseXSDuration parses a non-negative xs:duration such as "PT1H",
// "P7D" or "PT86400.5S".
func parseXSDuration(s string) (time.Duration, error) {
	if len(s) < 3 || s[0] != 'P' {
		return 0, errBadDuration
	}

	p := durationParser{rest: s[1:]}

	for p.rest != "" {
		if err := p.step(); err != nil {
			return 0, err
		}
	}

	if !p.sawUnit || (p.inTime && !p.sawTimeUnit) || p.total > math.MaxInt64 {
		return 0, errBadDuration
	}

	return time.Duration(p.total), nil
}

// durationParser holds the state of parseXSDuration.
type durationParser struct {
	rest        string
	total       float64
	next        int // index of the next allowed unit
	inTime      bool
	sawUnit     bool
	sawTimeUnit bool
}

// step consumes the "T" separator or one number and its designator.
func (p *durationParser) step() error {
	if p.rest[0] == 'T' {
		if p.inTime {
			return errBadDuration
		}

		p.inTime, p.sawTimeUnit = true, false
		p.rest = p.rest[1:]

		return nil
	}

	n := 0
	for n < len(p.rest) && (p.rest[n] >= '0' && p.rest[n] <= '9' || p.rest[n] == '.') {
		n++
	}

	if n == 0 || n == len(p.rest) {
		return errBadDuration
	}

	value, err := strconv.ParseFloat(p.rest[:n], 64)
	if err != nil {
		return errBadDuration
	}

	// Only the seconds may carry a fraction.
	idx, ok := durationUnitIndex(p.rest[n], p.inTime, p.next)
	if !ok || (p.rest[n] != 'S' && containsDot(p.rest[:n])) {
		return errBadDuration
	}

	p.total += value * float64(xsDurationUnits[idx].unit)
	p.next, p.sawUnit, p.sawTimeUnit = idx+1, true, true
	p.rest = p.rest[n+1:]

	return nil
}

// durationUnitIndex finds the unit for designator d in the date or time
// part, at or after index next (designators must appear in order, once).
func durationUnitIndex(d byte, inTime bool, next int) (int, bool) {
	for i := next; i < len(xsDurationUnits); i++ {
		u := xsDurationUnits[i]
		if u.designator == d && u.timePart == inTime {
			return i, true
		}
	}

	return 0, false
}

func containsDot(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			return true
		}
	}

	return false
}
