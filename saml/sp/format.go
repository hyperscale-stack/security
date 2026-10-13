// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp

import (
	"fmt"
	"io"
	"log/slog"
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
// of a non-pointer value before any method, as a bad verb printed with the
// value's fields: no type can redact that one (go vet reports it).
func formatRedacted(f fmt.State, verb rune, v redactedValue) {
	if verb == 'v' && f.Flag('#') {
		_, _ = io.WriteString(f, v.GoString())

		return
	}

	_, _ = io.WriteString(f, v.String())
}

// signingKeyState names whether a signing key is configured, never the key.
func signingKeyState(c Config) string {
	if c.SigningKey == nil {
		return "none"
	}

	return "REDACTED"
}

// String implements fmt.Stringer with the settings of the configuration:
// the signing key and the transaction keys are redacted, and the
// collaborators (resolver, stores, clock) left out. Every fmt verb and
// log/slog print a Config this way, except %p of a Config value (not a
// pointer), which fmt reports as a bad verb with every field: never print
// a Config with %p.
func (c Config) String() string {
	return fmt.Sprintf("samlsp.Config{SigningKey: %s, TransactionKeys: %d REDACTED, TransactionTTL: %s, ClockSkew: %s, "+
		"MaxResponseSize: %d, MetadataCacheDuration: %s, CookieName: %q}",
		signingKeyState(c), len(c.TransactionKeys), c.TransactionTTL, c.ClockSkew, c.MaxResponseSize,
		c.MetadataCacheDuration, c.CookieName)
}

// GoString implements fmt.GoStringer like String.
func (c Config) GoString() string { return c.String() }

// Format implements fmt.Formatter like String, for every verb.
func (c Config) Format(f fmt.State, verb rune) { formatRedacted(f, verb, c) }

// LogValue implements slog.LogValuer like String.
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("signing_key", signingKeyState(c)),
		slog.Int("transaction_keys", len(c.TransactionKeys)),
		slog.Duration("transaction_ttl", c.TransactionTTL),
		slog.Duration("clock_skew", c.ClockSkew),
		slog.Int64("max_response_size", c.MaxResponseSize),
		slog.Duration("metadata_cache_duration", c.MetadataCacheDuration),
		slog.String("cookie_name", c.CookieName),
	)
}

// String implements fmt.Stringer with the ServiceProvider's configuration,
// its keys redacted.
func (sp *ServiceProvider) String() string {
	if sp == nil {
		return "samlsp.ServiceProvider(nil)"
	}

	return "samlsp.ServiceProvider{" + sp.cfg.String() + "}"
}

// GoString implements fmt.GoStringer like String.
func (sp *ServiceProvider) GoString() string { return sp.String() }

// Format implements fmt.Formatter like String, for every verb: without it,
// fmt prints the unexported fields of a *ServiceProvider, keys included.
func (sp *ServiceProvider) Format(f fmt.State, verb rune) { formatRedacted(f, verb, sp) }

// LogValue implements slog.LogValuer with the ServiceProvider's
// configuration, its keys redacted.
func (sp *ServiceProvider) LogValue() slog.Value {
	if sp == nil {
		return slog.StringValue("samlsp.ServiceProvider(nil)")
	}

	return sp.cfg.LogValue()
}
