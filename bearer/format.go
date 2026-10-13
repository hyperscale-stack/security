// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package bearer

import (
	"fmt"
	"io"
	"log/slog"
)

// String implements fmt.Stringer with the name, the state and the
// authorities: the bearer token is never printed.
func (a Authentication) String() string {
	token := `""`
	if a.token != "" {
		token = "REDACTED"
	}

	return fmt.Sprintf("bearer.Authentication{Name: %q, Authenticated: %t, Authorities: %q, Token: %s}",
		a.Name(), a.authed, a.authorities, token)
}

// Format implements fmt.Formatter like String, for every verb, %#v
// included: without it, fmt prints the unexported fields — the token among
// them. fmt handles %p of a non-pointer value before any method: no type can
// redact that one.
func (a Authentication) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, a.String()) }

// LogValue implements slog.LogValuer like String.
func (a Authentication) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("name", a.Name()),
		slog.Bool("authenticated", a.authed),
		slog.Any("authorities", a.authorities),
	)
}
