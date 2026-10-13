// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package param reads OAuth 2.0 request parameters for the oauth2 module,
// applying RFC 6749 §3.1 and §3.2: "Parameters sent without a value MUST be
// treated as if they were omitted from the request. The authorization
// server MUST ignore unrecognized request parameters. Request and response
// parameters MUST NOT be included more than once."
package param

import "net/url"

// Value returns the value of the request parameter name in form: its first
// non-empty occurrence. An empty occurrence is an omitted parameter: it
// never hides the value that follows it.
func Value(form url.Values, name string) string {
	for _, v := range form[name] {
		if v != "" {
			return v
		}
	}

	return ""
}

// SingleValued returns a copy of form in which every parameter of names
// holds its one non-empty value — or is absent when it has none — and the
// first of names, in their order, that form includes more than once with a
// value ("" when none): that parameter is absent from the copy. Every other
// parameter is copied as received: the server ignores what it does not
// recognize, and its callbacks refuse their own repetitions. form is not
// modified; the copy shares its value slices.
func SingleValued(form url.Values, names []string) (url.Values, string) {
	out := make(url.Values, len(form))
	for k, v := range form {
		out[k] = v
	}

	repeated := ""

	for _, name := range names {
		value, n := "", 0

		for _, v := range form[name] {
			if v != "" {
				value, n = v, n+1
			}
		}

		switch {
		case n == 1:
			out[name] = []string{value}
		case n > 1 && repeated == "":
			repeated = name

			delete(out, name)
		default:
			delete(out, name)
		}
	}

	return out, repeated
}
