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

// Extractor implements [security.Extractor] for the Bearer scheme
// (RFC 6750 §2.1). It reads the Authorization header from the Carrier and
// hands the opaque token to a [TokenVerifier] downstream.
type Extractor struct{}

// NewExtractor returns the canonical zero-config Extractor reading the
// Authorization header.
func NewExtractor() Extractor { return Extractor{} }

// Extract implements [security.Extractor]. Returns (nil, nil) when no
// Bearer credentials are present (next extractor gets a chance). Returns
// a non-nil Authentication carrying the raw token when the header is
// well-formed; the verifier is responsible for validating the token shape.
// A repeated Authorization field is refused with an error wrapping
// [security.ErrInvalidRequest] (RFC 9110 §5.3, RFC 6750 §3.1).
func (Extractor) Extract(_ context.Context, c security.Carrier) (security.Authentication, error) {
	header, err := security.SingleValue(c, "Authorization")
	if err != nil {
		return nil, fmt.Errorf("bearer: %w", err)
	}

	if header == "" {
		return nil, nil
	}

	token, ok := extractValue(scheme, header)
	if !ok {
		return nil, nil
	}

	if token == "" {
		return nil, nil
	}

	return New(token), nil
}

// extractValue strips a case-insensitive scheme prefix from an Authorization
// header value. Local copy so this module stays free of an httpsec dep.
func extractValue(scheme, header string) (string, bool) {
	prefix := scheme + " "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}

	return header[len(prefix):], true
}
