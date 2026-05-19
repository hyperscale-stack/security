// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package bearer

import (
	"context"
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
func (Extractor) Extract(_ context.Context, c security.Carrier) (security.Authentication, error) {
	header := c.Get("Authorization")
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

// QueryExtractor reads the bearer token from a query parameter. Provided
// for transports that historically used "?access_token=..." (RFC 6750 §2.3)
// but DEPRECATED: query-borne tokens leak into access logs, browser
// history, and Referer headers.
//
// Only enable this extractor when interoperating with legacy clients you
// cannot migrate; otherwise prefer [Extractor].
type QueryExtractor struct{ ParamName string }

// NewQueryExtractor returns a [QueryExtractor] reading the named query
// parameter. paramName defaults to "access_token" when empty.
//
// Deprecated: prefer [NewExtractor] (header-based). Query-borne tokens leak
// into access logs and browser history. See RFC 6750 §5.3 ("Bearer Token
// in the URI"); the entire section is a list of reasons not to use it.
func NewQueryExtractor(paramName string) QueryExtractor {
	if paramName == "" {
		paramName = "access_token"
	}

	return QueryExtractor{ParamName: paramName}
}

// Extract implements [security.Extractor].
func (q QueryExtractor) Extract(_ context.Context, c security.Carrier) (security.Authentication, error) {
	token := c.Get(q.ParamName)
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
