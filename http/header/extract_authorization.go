// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package header

import (
	"strings"
)

// ExtractAuthorizationValue returns the value without t
func ExtractAuthorizationValue(t string, value string) (string, bool) {
	prefix := t + " "

	if len(value) < len(prefix) || !strings.EqualFold(value[:len(prefix)], prefix) {
		return "", false
	}

	return value[len(prefix):], true
}
