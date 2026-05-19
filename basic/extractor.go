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

	"github.com/hyperscale-stack/security"
)

// ErrBadFormat is returned by the [Extractor] when the Authorization header
// carries a Basic scheme but the payload cannot be decoded (invalid base64,
// missing colon, ...). It is wrapped around [security.ErrInvalidCredentials]
// so error mappers route it to 401 — and to prevent oracle attacks that
// distinguish "malformed" from "wrong".
var ErrBadFormat = errors.New("basic: malformed credentials")

const scheme = "Basic"

// Extractor implements [security.Extractor] for the HTTP Basic scheme
// (RFC 7617). It reads the Authorization header from the Carrier and parses
// the base64-encoded "username:password" payload. The scheme prefix is
// matched case-insensitively per RFC 7235 §2.1.
type Extractor struct{}

// NewExtractor returns the canonical zero-config Extractor.
func NewExtractor() Extractor { return Extractor{} }

// Extract implements [security.Extractor]. Returns (nil, nil) when no Basic
// credentials are present (next extractor gets a chance); a non-nil error
// for credentials that are present but malformed.
func (Extractor) Extract(_ context.Context, c security.Carrier) (security.Authentication, error) {
	header := c.Get("Authorization")
	if header == "" {
		return nil, nil
	}

	payload, ok := extractValue(scheme, header)
	if !ok {
		// Header carries some other scheme (Bearer, Digest...). Let
		// downstream extractors try.
		return nil, nil
	}

	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("basic: base64 decode: %w (%w)", ErrBadFormat, security.ErrInvalidCredentials)
	}

	colon := strings.IndexByte(string(raw), ':')
	if colon < 0 {
		return nil, fmt.Errorf("basic: missing colon separator: %w (%w)", ErrBadFormat, security.ErrInvalidCredentials)
	}

	return New(string(raw[:colon]), string(raw[colon+1:])), nil
}

// extractValue is the case-insensitive scheme-stripper. Duplicated locally to
// avoid a transport-shaped dependency on httpsec (which would create a cycle
// once httpsec composes basic.Extractor).
func extractValue(scheme, header string) (string, bool) {
	prefix := scheme + " "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}

	return header[len(prefix):], true
}
