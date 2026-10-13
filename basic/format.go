// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package basic

import (
	"fmt"
	"io"
	"log/slog"
)

// String implements fmt.Stringer with the name — the authenticated subject,
// or "basic" — the state and the authorities: never the typed user-id (it
// may be a password typed in the wrong field), the password, nor the
// resolved PasswordUser (the application's user record, its password hash
// included).
func (a Authentication) String() string {
	credentials := `""`
	if a.password != "" {
		credentials = "REDACTED"
	}

	return fmt.Sprintf("basic.Authentication{Name: %q, Authenticated: %t, Authorities: %q, Credentials: %s}",
		a.Name(), a.authed, a.authorities, credentials)
}

// Format implements fmt.Formatter like String, for every verb, %#v
// included: without it, fmt prints the unexported fields — the password and
// the user record. fmt handles %p of a non-pointer value before any method:
// no type can redact that one.
func (a Authentication) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, a.String()) }

// LogValue implements slog.LogValuer like String.
func (a Authentication) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("name", a.Name()),
		slog.Bool("authenticated", a.authed),
		slog.Any("authorities", a.authorities),
	)
}
