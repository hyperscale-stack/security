// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package httpsec

import "strings"

// ExtractAuthorizationValue parses an "Authorization" header value of the
// form "<scheme> 1*SP <value>" (RFC 9110 §11.4) and returns (value, true)
// when its first word is scheme, matched case-insensitively (§11.1), the
// spaces stripped. The scheme alone — or followed by spaces only — gives
// ("", true): refuse such a credential, it carries nothing. It returns
// ("", false) when the first word is another scheme, or when the scheme is
// not followed by a space or the end ("BearerX", a tab).
//
// The basic and bearer extractors carry their own, stricter parsers to
// stay free of an httpsec dependency; this one is for application
// extractors, which validate the value's own syntax.
func ExtractAuthorizationValue(scheme, header string) (string, bool) {
	if len(header) < len(scheme) || !strings.EqualFold(header[:len(scheme)], scheme) {
		return "", false
	}

	rest := header[len(scheme):]
	if rest != "" && rest[0] != ' ' {
		return "", false
	}

	return strings.TrimLeft(rest, " "), true
}
