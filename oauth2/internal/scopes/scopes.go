// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package scopes parses and compares OAuth 2.0 scope values (RFC 6749 §3.3)
// for the oauth2 module: one strict, single-pass parser with bounds, and
// map-based sets, so the work a scope value can cause stays linear in its
// size and bounded.
//
// Values a client or a callback sends go through [Parse]. Values the server
// stored itself — a code's or a token's scope — are split leniently by the
// callers (strings.Fields): a record written before the syntax was enforced
// is never refused for its own scope.
package scopes

import (
	"errors"
	"strings"
)

// Bounds of a scope value the server accepts.
const (
	// MaxLength is the longest scope value accepted, in bytes.
	MaxLength = 4096
	// MaxTokens is the largest number of scope tokens in one value,
	// repetitions included.
	MaxTokens = 100
)

// Why a scope value is refused. Callers answer both with invalid_scope.
var (
	// ErrMalformed reports a scope value outside the RFC 6749 §3.3 syntax.
	ErrMalformed = errors.New("oauth2: scope outside the RFC 6749 §3.3 syntax")
	// ErrTooLarge reports a scope value over MaxLength bytes or MaxTokens
	// tokens.
	ErrTooLarge = errors.New("oauth2: scope over 4096 bytes or 100 tokens")
)

// Parse returns the distinct scope tokens of s, in order of first
// occurrence (RFC 6749 §3.3: case-sensitive strings whose order does not
// matter). Tokens are separated by SP (U+0020) — runs of SP and leading or
// trailing SPs carry no token and are tolerated, a deliberate leniency over
// the §3.3 ABNF — and each token is 1*NQCHAR (%x21 / %x23-5B / %x5D-7E,
// Appendix A): any other byte — another whitespace, a quote, a backslash, a
// control or a non-ASCII byte — makes s malformed. An empty or all-SP s has
// no token. A value over MaxLength bytes is refused before it is read, and
// the scan stops at the (MaxTokens+1)th token, repetitions included.
func Parse(s string) ([]string, error) {
	if len(s) > MaxLength {
		return nil, ErrTooLarge
	}

	var (
		tokens []string
		seen   Set
		count  int
		start  = -1
	)

	for i := 0; i <= len(s); i++ {
		if i < len(s) && s[i] != ' ' {
			if !nqchar(s[i]) {
				return nil, ErrMalformed
			}

			if start < 0 {
				start = i
			}

			continue
		}

		if start < 0 {
			continue
		}

		if count++; count > MaxTokens {
			return nil, ErrTooLarge
		}

		token := s[start:i]
		start = -1

		if seen.has(token) {
			continue
		}

		if seen == nil {
			seen = Set{}
		}

		seen[token] = struct{}{}
		tokens = append(tokens, token)
	}

	return tokens, nil
}

// nqchar reports whether b is an RFC 6749 Appendix A NQCHAR: printable
// ASCII but the double quote and the backslash.
func nqchar(b byte) bool {
	return b >= 0x21 && b <= 0x7e && b != '"' && b != '\\'
}

// Set is a set of scope tokens. Lookups are map lookups: checking a request
// against a registration costs one per requested token, whatever the size
// of the registration.
type Set map[string]struct{}

// NewSet returns the set of tokens.
func NewSet(tokens []string) Set {
	set := make(Set, len(tokens))

	for _, t := range tokens {
		set[t] = struct{}{}
	}

	return set
}

// has reports whether token is in s; a nil s holds nothing.
func (s Set) has(token string) bool {
	_, ok := s[token]

	return ok
}

// Admits reports whether every token is in s. An empty s admits no token;
// any s admits an empty list.
func (s Set) Admits(tokens []string) bool {
	for _, t := range tokens {
		if !s.has(t) {
			return false
		}
	}

	return true
}

// Join renders tokens as a scope value: single-SP separated, the canonical
// form the server issues and stores.
func Join(tokens []string) string {
	return strings.Join(tokens, " ")
}
