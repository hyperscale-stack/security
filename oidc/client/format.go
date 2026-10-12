// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient

import (
	"fmt"
	"io"
	"log/slog"
	"time"
)

// redactedValue is a type that holds a secret and prints without it.
type redactedValue interface {
	fmt.Stringer
	fmt.GoStringer
}

// formatRedacted implements fmt.Formatter for the types that hold secrets:
// every verb prints their String — %#v their GoString — so that no verb
// falls back to printing their fields, as fmt does for the verbs a String
// method does not cover (%d, %t…) and for unexported fields. fmt handles %p
// of a non-pointer value before any method: no type can redact that one.
func formatRedacted(f fmt.State, verb rune, v redactedValue) {
	if verb == 'v' && f.Flag('#') {
		_, _ = io.WriteString(f, v.GoString())

		return
	}

	_, _ = io.WriteString(f, v.String())
}

// Format implements fmt.Formatter like String, for every verb.
func (c Config) Format(f fmt.State, verb rune) { formatRedacted(f, verb, c) }

// Format implements fmt.Formatter like String, for every verb.
func (r AuthRequest) Format(f fmt.State, verb rune) { formatRedacted(f, verb, r) }

// Format implements fmt.Formatter like String, for every verb.
func (cb Callback) Format(f fmt.State, verb rune) { formatRedacted(f, verb, cb) }

// Format implements fmt.Formatter like String, for every verb.
func (t Tokens) Format(f fmt.State, verb rune) { formatRedacted(f, verb, t) }

// String implements fmt.Stringer with the identifiers of the login: its
// tokens are redacted and its claims left out.
func (id Identity) String() string {
	return fmt.Sprintf("oidcclient.Identity{ConnectionID: %q, Issuer: %q, Subject: %q, AuthTime: %s, ACR: %q, Tokens: %s}",
		id.ConnectionID, id.Issuer, id.Subject, id.AuthTime.Format(time.RFC3339), id.ACR, id.Tokens.String())
}

// GoString implements fmt.GoStringer like String.
func (id Identity) GoString() string { return id.String() }

// Format implements fmt.Formatter like String, for every verb.
func (id Identity) Format(f fmt.State, verb rune) { formatRedacted(f, verb, id) }

// String implements fmt.Stringer with the Client's configuration, its
// client secret and transaction keys redacted.
func (c *Client) String() string {
	if c == nil {
		return "oidcclient.Client(nil)"
	}

	return "oidcclient.Client{" + c.cfg.String() + "}"
}

// GoString implements fmt.GoStringer like String.
func (c *Client) GoString() string { return c.String() }

// Format implements fmt.Formatter like String, for every verb: without it,
// fmt prints the unexported fields of a *Client, secrets included.
func (c *Client) Format(f fmt.State, verb rune) { formatRedacted(f, verb, c) }

// LogValue implements slog.LogValuer with the Client's configuration, its
// secrets redacted.
func (c *Client) LogValue() slog.Value {
	if c == nil {
		return slog.StringValue("oidcclient.Client(nil)")
	}

	return c.cfg.LogValue()
}
