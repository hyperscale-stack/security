// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient

import (
	"encoding/json"
	"fmt"
	"log/slog"
)

// Secret is a credential of the Relying Party: the client secret, a
// transaction key, the binding secret of a login, a token. Reveal returns
// its value; every other rendering prints REDACTED — "" for an empty
// Secret — so that no log, error or dump carries it:
//
//   - fmt, with every verb, flag and width (Format), String and GoString;
//   - log/slog, as an attribute (LogValue) or nested in a struct that the
//     text handler prints with fmt;
//   - encoding/json (MarshalJSON), log/slog's JSON handler included. A
//     Secret does not decode from JSON: a REDACTED document never turns
//     back into a credential;
//   - a Secret reached through an unexported field of another value, which
//     fmt prints by reflection without calling any method: its value sits
//     behind a pointer to a string, which fmt then renders as an address,
//     whatever the verb. encoding/gob refuses a Secret (it has no exported
//     field) and encoding/xml writes it empty.
//
// The zero Secret is empty. A Secret is immutable and safe to copy and
// share between goroutines. Compare two Secrets with crypto/subtle on their
// revealed values, never with ==, which compares their identity. Reveal a
// Secret only where the credential is used: in a request to the provider,
// in a cookie, in the application's own secure storage.
type Secret struct {
	// v points to a string — never a struct, slice or map, which fmt
	// expands when it reports a bad verb for a value it reached by
	// reflection, printing their content. nil for an empty Secret.
	v *string
}

// NewSecret returns the Secret holding value; the zero Secret for "".
func NewSecret(value string) Secret {
	if value == "" {
		return Secret{}
	}

	return Secret{v: &value}
}

// Reveal returns the value of the Secret, "" for an empty one.
func (s Secret) Reveal() string {
	if s.v == nil {
		return ""
	}

	return *s.v
}

// String implements fmt.Stringer: REDACTED, or "" when the Secret is empty.
func (s Secret) String() string {
	if s.Reveal() == "" {
		return `""`
	}

	return redactedMark
}

// GoString implements fmt.GoStringer like String.
func (s Secret) GoString() string { return s.String() }

// Format implements fmt.Formatter like String, for every verb.
func (s Secret) Format(f fmt.State, verb rune) { formatRedacted(f, verb, s) }

// LogValue implements slog.LogValuer like String.
func (s Secret) LogValue() slog.Value { return slog.StringValue(s.String()) }

// MarshalJSON implements json.Marshaler: "REDACTED", or "" when the Secret
// is empty.
func (s Secret) MarshalJSON() ([]byte, error) {
	if s.Reveal() == "" {
		return []byte(`""`), nil
	}

	return json.Marshal(redactedMark) //nolint:wrapcheck // a constant string: never fails
}
