// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package basic

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/hyperscale-stack/security"
)

// ErrBadFormat is returned by the [Extractor] when the Authorization header
// carries a Basic scheme but the credentials are malformed (not base64,
// missing colon, control characters, not UTF-8, too long, ...), and by the
// [Authenticator] for a user-id or password it refuses before any lookup.
// It is wrapped around [security.ErrInvalidCredentials] so error mappers
// route it to 401 — and to prevent oracle attacks that distinguish
// "malformed" from "wrong".
var ErrBadFormat = errors.New("basic: malformed credentials")

const scheme = "Basic"

// Bounds of the credentials. maxCredentialsLength bounds the base64
// credentials of the Authorization header; maxUserPassLength the decoded
// "user-id:password" (what 4096 base64 characters decode to). RFC 7617 sets
// no limit; these are far above any real password and keep hostile input
// away from the loader and the hasher.
const (
	maxCredentialsLength = 4096
	maxUserPassLength    = 3072
)

// Extractor implements [security.Extractor] for the HTTP Basic scheme
// (RFC 7617). It reads the Authorization header from the Carrier and parses
// the base64-encoded "user-id:password" payload. The scheme is matched
// case-insensitively and may be followed by several spaces (RFC 9110 §11.4).
//
// It is strict: the credentials must use the base64 alphabet with canonical
// padding (RFC 4648 §4, §3.5), the user-id and password must be valid UTF-8
// without any control character (RFC 7617 §2 "MUST NOT contain any control
// characters"; C1 controls included, RFC 8264 §9.12), and the decoded
// user-pass is at most 3072 bytes. Malformed credentials are refused before
// they reach any [UserLoader] — they are never logged nor looked up. An
// empty user-id or password is syntactically valid and let through (custom
// authenticators accept API keys sent as `-u :KEY`); the [Authenticator]
// refuses an empty user-id.
type Extractor struct{}

// NewExtractor returns the canonical zero-config Extractor.
func NewExtractor() Extractor { return Extractor{} }

// Extract implements [security.Extractor]. Returns (nil, nil) when no Basic
// credentials are present (next extractor gets a chance); a non-nil error
// wrapping [ErrBadFormat] for credentials that are present but malformed,
// and one wrapping [security.ErrInvalidRequest] when the Authorization field
// is repeated (RFC 9110 §5.3).
func (Extractor) Extract(_ context.Context, c security.Carrier) (security.Authentication, error) {
	header, err := security.SingleValue(c, "Authorization")
	if err != nil {
		return nil, fmt.Errorf("basic: %w", err)
	}

	if header == "" {
		return nil, nil
	}

	payload, ok := extractValue(scheme, header)
	if !ok {
		// Header carries some other scheme (Bearer, Digest...). Let
		// downstream extractors try.
		return nil, nil
	}

	username, password, err := decodeCredentials(payload)
	if err != nil {
		return nil, err
	}

	return New(username, password), nil
}

// decodeCredentials decodes the token68 credentials of RFC 7617 §2 and
// checks the user-id and the password.
func decodeCredentials(payload string) (string, string, error) {
	if payload == "" || len(payload) > maxCredentialsLength || strings.IndexFunc(payload, notBase64) >= 0 {
		// Checked before decoding: encoding/base64 silently skips CR and LF.
		return "", "", malformed("credentials are not base64")
	}

	raw, err := base64.StdEncoding.Strict().DecodeString(payload)
	if err != nil {
		return "", "", malformed("credentials are not canonical base64")
	}

	username, password, ok := strings.Cut(string(raw), ":")
	if !ok {
		return "", "", malformed("missing colon separator")
	}

	if err := checkUserPass(username, password); err != nil {
		return "", "", err
	}

	return username, password, nil
}

// checkUserPass applies the rules the [Extractor] and the [Authenticator]
// share: UTF-8 without any control character (RFC 7617 §2, RFC 8264 §9.12)
// and a bounded length. The reason never quotes the input.
func checkUserPass(username, password string) error {
	switch {
	case len(username)+1+len(password) > maxUserPassLength:
		return malformed("credentials longer than 3072 bytes")
	case !utf8.ValidString(username) || !utf8.ValidString(password):
		return malformed("credentials are not UTF-8")
	case strings.IndexFunc(username, unicode.IsControl) >= 0 || strings.IndexFunc(password, unicode.IsControl) >= 0:
		return malformed("control character in the credentials")
	}

	return nil
}

// malformed wraps ErrBadFormat and security.ErrInvalidCredentials.
func malformed(reason string) error {
	return fmt.Errorf("basic: %s: %w (%w)", reason, ErrBadFormat, security.ErrInvalidCredentials)
}

// notBase64 reports whether r is outside the base64 alphabet of RFC 4648 §4
// (padding included).
func notBase64(r rune) bool {
	switch {
	case 'A' <= r && r <= 'Z', 'a' <= r && r <= 'z', '0' <= r && r <= '9', r == '+', r == '/', r == '=':
		return false
	}

	return true
}

// extractValue is the case-insensitive scheme-stripper: the scheme, then
// one or more spaces, then the credentials ("" when the scheme stands
// alone). A header whose first word merely starts with the scheme
// ("BasicAuth") is another scheme. Duplicated locally to avoid a
// transport-shaped dependency on httpsec (which would create a cycle once
// httpsec composes basic.Extractor).
func extractValue(scheme, header string) (string, bool) {
	if len(header) < len(scheme) || !strings.EqualFold(header[:len(scheme)], scheme) {
		return "", false
	}

	rest := header[len(scheme):]
	if rest != "" && rest[0] != ' ' {
		return "", false
	}

	return strings.TrimLeft(rest, " "), true
}
