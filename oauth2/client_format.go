// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"fmt"
	"io"
	"log/slog"
)

// String implements fmt.Stringer with the client's registration, its
// secret redacted.
func (c DefaultClient) String() string {
	secret := `""`
	if c.Secret != "" {
		secret = "REDACTED"
	}

	return fmt.Sprintf("oauth2.DefaultClient{ID: %q, Type: %q, Secret: %s, RedirectURIs: %q, GrantTypes: %q, Scopes: %q, AuthMethods: %q, Issuers: %q}",
		c.IDValue, string(c.TypeValue), secret, c.RedirectURIValues, c.GrantTypeValues, c.ScopeValues, c.AuthMethodValues, c.IssuerValues)
}

// GoString implements fmt.GoStringer like String.
func (c DefaultClient) GoString() string { return c.String() }

// Format implements fmt.Formatter like String, for every verb: without it,
// fmt prints the fields — the secret included — for the verbs String does
// not cover (%d, %t…). fmt handles %p of a non-pointer value before any
// method: no type can redact that one.
func (c DefaultClient) Format(f fmt.State, verb rune) {
	if verb == 'v' && f.Flag('#') {
		_, _ = io.WriteString(f, c.GoString())

		return
	}

	_, _ = io.WriteString(f, c.String())
}

// LogValue implements slog.LogValuer with the client's registration, never
// its secret.
func (c DefaultClient) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", c.IDValue),
		slog.String("type", string(c.TypeValue)),
		slog.Bool("has_secret", c.Secret != ""),
		slog.Any("redirect_uris", c.RedirectURIValues),
		slog.Any("grant_types", c.GrantTypeValues),
		slog.Any("scopes", c.ScopeValues),
		slog.Any("auth_methods", c.AuthMethodValues),
		slog.Any("issuers", c.IssuerValues),
	)
}
