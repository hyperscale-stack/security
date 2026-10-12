// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package param_test

import (
	"net/url"
	"testing"

	"github.com/hyperscale-stack/security/oauth2/internal/param"
	"github.com/stretchr/testify/assert"
)

// TestValue pins RFC 6749 §3.1 / §3.2: "Parameters sent without a value MUST
// be treated as if they were omitted from the request" — an empty occurrence
// never hides the value that follows it.
func TestValue(t *testing.T) {
	t.Parallel()

	form := url.Values{"a": {"", "x"}, "b": {"y", ""}, "c": {""}, "d": {"first", "second"}}

	assert.Equal(t, "x", param.Value(form, "a"))
	assert.Equal(t, "y", param.Value(form, "b"))
	assert.Empty(t, param.Value(form, "c"))
	assert.Empty(t, param.Value(form, "absent"))
	assert.Equal(t, "first", param.Value(form, "d"))
}

// TestSingleValued pins RFC 6749 §3.1 / §3.2: a parameter the server
// recognizes MUST NOT be included more than once — an empty occurrence is
// none — and unrecognized parameters are left alone.
func TestSingleValued(t *testing.T) {
	t.Parallel()

	names := []string{"scope", "state", "code"}

	cases := []struct {
		name     string
		form     url.Values
		want     url.Values
		repeated string
	}{
		{"absent", url.Values{}, url.Values{}, ""},
		{"single", url.Values{"scope": {"read"}}, url.Values{"scope": {"read"}}, ""},
		{"empty only: omitted", url.Values{"scope": {"", ""}}, url.Values{}, ""},
		{"empty first", url.Values{"scope": {"", "read"}}, url.Values{"scope": {"read"}}, ""},
		{"empty last", url.Values{"scope": {"read", ""}}, url.Values{"scope": {"read"}}, ""},
		{"repeated", url.Values{"scope": {"read", "write"}, "state": {"s"}}, url.Values{"state": {"s"}}, "scope"},
		{"first repeated in names order", url.Values{"code": {"a", "b"}, "state": {"1", "2"}}, url.Values{}, "state"},
		{"unrecognized repeated: kept", url.Values{"foo": {"a", "b"}}, url.Values{"foo": {"a", "b"}}, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			before := url.Values{}
			for k, v := range tc.form {
				before[k] = append([]string(nil), v...)
			}

			got, repeated := param.SingleValued(tc.form, names)
			assert.Equal(t, tc.repeated, repeated)

			if repeated == "" {
				assert.Equal(t, tc.want, got)
			} else {
				assert.NotContains(t, got, repeated, "a repeated parameter has no value")
			}

			assert.Equal(t, before, tc.form, "the input is not modified")
		})
	}
}
