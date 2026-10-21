// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package bearer

import (
	"context"
	"fmt"
	"strings"

	"github.com/hyperscale-stack/security"
)

const scheme = "Bearer"

// DefaultMaxTokenLength is the longest token the [Extractor] hands to a
// [TokenVerifier] by default: 16 KiB, the bound jwtsec.DefaultMaxTokenSize
// gives JWT access tokens. Raise both together.
const DefaultMaxTokenLength = 16 << 10

// Extractor implements [security.Extractor] for the Bearer scheme
// (RFC 6750 §2.1). It reads the Authorization header from the Carrier and
// hands the token to a [TokenVerifier] downstream. The zero value uses
// [DefaultMaxTokenLength].
type Extractor struct {
	maxLength int
}

// ExtractorOption configures an [Extractor].
type ExtractorOption func(*Extractor)

// WithMaxTokenLength sets the longest token the Extractor accepts, in
// bytes. Default: [DefaultMaxTokenLength]. It panics unless n ≥ 1.
func WithMaxTokenLength(n int) ExtractorOption {
	if n < 1 {
		panic(fmt.Sprintf("bearer: WithMaxTokenLength: %d is not positive", n))
	}

	return func(e *Extractor) { e.maxLength = n }
}

// NewExtractor returns an Extractor reading the Authorization header.
func NewExtractor(opts ...ExtractorOption) Extractor {
	var e Extractor

	for _, o := range opts {
		o(&e)
	}

	return e
}

// Extract implements [security.Extractor]. It returns (nil, nil) when the
// Authorization field is absent or carries another scheme — its first
// word, ended by a space or a tab, is not "Bearer" (case-insensitive,
// RFC 9110 §11.1) —, so that the next extractor gets a chance.
//
// A Bearer credential must follow RFC 6750 §2.1 to the letter —
// `credentials = "Bearer" 1*SP b64token`, `b64token = 1*( ALPHA / DIGIT /
// "-" / "." / "_" / "~" / "+" / "/" ) *"="`: one or more spaces, then the
// token and nothing else. The scheme alone, a tab, an empty token, a
// character outside the b64token alphabet, padding before the end, a
// second word or credential are refused with an error wrapping
// [security.ErrInvalidRequest] — a malformed request, HTTP 400
// invalid_request (§3.1). A token over the length cap ([WithMaxTokenLength],
// checked first) is refused with an error wrapping
// [security.ErrInvalidCredentials] — 401 invalid_token, "invalid for other
// reasons" (§3.1). A repeated Authorization field is refused with
// [security.ErrInvalidRequest] too (RFC 9110 §5.3). No refused value
// reaches the verifier, and no error quotes it.
func (e Extractor) Extract(_ context.Context, c security.Carrier) (security.Authentication, error) {
	header, err := security.SingleValue(c, "Authorization")
	if err != nil {
		return nil, fmt.Errorf("bearer: %w", err)
	}

	if header == "" {
		return nil, nil
	}

	rest, ok := cutScheme(header)
	if !ok {
		return nil, nil
	}

	token, err := e.parse(rest)
	if err != nil {
		return nil, err
	}

	return New(token), nil
}

// cutScheme returns what follows the scheme when the first word of header
// — ended by a space, a tab or the end — is the Bearer scheme.
func cutScheme(header string) (string, bool) {
	end := strings.IndexAny(header, " \t")
	if end < 0 {
		end = len(header)
	}

	if !strings.EqualFold(header[:end], scheme) {
		return "", false
	}

	return header[end:], true
}

// parse checks what follows the scheme — 1*SP b64token — and returns the
// token. The spaces are stripped: nothing else — no tab, no empty token —
// is a b64token.
func (e Extractor) parse(rest string) (string, error) {
	token := strings.TrimLeft(rest, " ")

	maxLength := e.maxLength
	if maxLength == 0 {
		maxLength = DefaultMaxTokenLength
	}

	switch {
	case len(token) > maxLength:
		return "", fmt.Errorf("bearer: token longer than %d bytes: %w", maxLength, security.ErrInvalidCredentials)
	case !isB64token(token):
		return "", malformed("the token is not an RFC 6750 b64token")
	}

	return token, nil
}

// malformed wraps security.ErrInvalidRequest.
func malformed(reason string) error {
	return fmt.Errorf("bearer: malformed credentials: %s: %w", reason, security.ErrInvalidRequest)
}

// isB64token reports whether s is an RFC 6750 §2.1 b64token: one or more
// characters of the alphabet, then only "=" padding.
func isB64token(s string) bool {
	body := strings.TrimRight(s, "=")
	if body == "" {
		return false
	}

	for i := range len(body) {
		c := body[i]

		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9':
		case c == '-', c == '.', c == '_', c == '~', c == '+', c == '/':
		default:
			return false
		}
	}

	return true
}
