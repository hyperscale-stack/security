// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package httpsec

import "strings"

// ExtractAuthorizationValue parses an "Authorization" header value of the
// form "<scheme> <value>" and returns the (value, true) pair when scheme
// matches case-insensitively. It returns ("", false) when the input does
// not start with the expected scheme — the canonical fast-path for
// scheme-specific extractors (Basic, Bearer, etc.).
//
// This is the v2 replacement of the legacy internal/header.ExtractAuthorizationValue
// helper; sub-modules (basic, bearer) MUST consume this version.
func ExtractAuthorizationValue(scheme, header string) (string, bool) {
	prefix := scheme + " "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}

	return header[len(prefix):], true
}
