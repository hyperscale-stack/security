// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package clientauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestFormValue: a body parameter is its first non-empty occurrence (RFC
// 6749 §3.1: an empty one is omitted), the form is parsed when the caller
// has not, and a body that cannot be parsed holds no parameter.
func TestFormValue(t *testing.T) {
	t.Parallel()

	post := func(body string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		return r
	}

	assert.Equal(t, "pub", formValue(post("client_id=&client_id=pub"), "client_id"))
	assert.Empty(t, formValue(post("client_id="), "client_id"))
	assert.Empty(t, formValue(post("client_id=%zz"), "client_id"), "a malformed body holds no parameter")
}
