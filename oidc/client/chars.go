// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient

// Lower bounds of the ASCII character classes the package validates.
const (
	// printableASCII starts VSCHAR (RFC 6749 Appendix A): %x20-7E.
	printableASCII byte = 0x20
	// visibleASCII excludes the space: %x21-7E.
	visibleASCII byte = 0x21
)

// isASCII reports whether s holds 1 to maxLen bytes, each between low and
// 0x7E.
func isASCII(s string, low byte, maxLen int) bool {
	if s == "" || len(s) > maxLen {
		return false
	}

	for i := range len(s) {
		if s[i] < low || s[i] > 0x7E {
			return false
		}
	}

	return true
}

// isLowerHex reports whether s holds exactly n lowercase hex digits.
func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}

	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}

	return true
}
