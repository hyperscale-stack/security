// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"slices"
	"time"
)

// redacted stands for a secret wherever a session is printed, logged or
// encoded.
const redacted = "REDACTED"

// redact renders a secret as REDACTED, or as "" when it is empty.
func redact(secret string) string {
	if secret == "" {
		return `""`
	}

	return redacted
}

// fingerprint renders a session ID as its SHA-256 fingerprint (the
// session.id_hash span attribute), or "" when it is empty: the raw ID is a
// credential.
func fingerprint(id string) string {
	if id == "" {
		return `""`
	}

	return hashID(id)
}

// valueKeys returns the sorted keys of the session values: the values
// themselves are application data — tokens, personal data — and are never
// printed.
func valueKeys(values map[string]any) []string {
	return slices.Sorted(maps.Keys(values))
}

// String implements fmt.Stringer: the ID as its fingerprint, the keys of the
// values, the times — never the CSRF token, the raw ID or the values. The
// cookie carries everything: the redaction applies to printing only.
func (s Session) String() string {
	return fmt.Sprintf("session.Session{ID: %s, Values: %s, CSRFToken: %s, CreatedAt: %s, LastAccessed: %s, ExpiresAt: %s}",
		fingerprint(s.ID), valueKeys(s.Values), redact(s.CSRFToken),
		s.CreatedAt.Format(time.RFC3339), s.LastAccessed.Format(time.RFC3339), s.ExpiresAt.Format(time.RFC3339))
}

// Format implements fmt.Formatter like String, for every verb, %#v
// included: without it, fmt prints the exported fields — the CSRF token
// among them. fmt handles %p of a non-pointer value before any method: no
// type can redact that one.
func (s Session) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }

// LogValue implements slog.LogValuer like String.
func (s Session) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id_hash", fingerprint(s.ID)),
		slog.Any("values", valueKeys(s.Values)),
		slog.Time("created_at", s.CreatedAt),
		slog.Time("last_accessed", s.LastAccessed),
		slog.Time("expires_at", s.ExpiresAt),
	)
}

// sessionJSON is the encoding/json form of a Session.
type sessionJSON struct {
	IDHash       string    `json:"IDHash,omitempty"`
	Values       []string  `json:"Values"`
	CSRFToken    string    `json:"CSRFToken,omitempty"`
	CreatedAt    time.Time `json:"CreatedAt"`
	LastAccessed time.Time `json:"LastAccessed"`
	ExpiresAt    time.Time `json:"ExpiresAt"`
}

// MarshalJSON implements json.Marshaler like String: log/slog's JSON handler
// encodes a Session nested in another value with encoding/json, which would
// otherwise write the CSRF token and the values. A Session is persisted
// sealed in its cookie by the Manager, never with encoding/json; an
// application that stores sessions itself uses its own type.
func (s Session) MarshalJSON() ([]byte, error) {
	out := sessionJSON{
		Values: valueKeys(s.Values), CreatedAt: s.CreatedAt, LastAccessed: s.LastAccessed, ExpiresAt: s.ExpiresAt,
	}

	if s.ID != "" {
		out.IDHash = hashID(s.ID)
	}

	if s.CSRFToken != "" {
		out.CSRFToken = redacted
	}

	return json.Marshal(out) //nolint:wrapcheck // strings and times only: never fails
}

// String implements fmt.Stringer with the name, the state and the
// authorities: never the session it holds nor the application's principal.
func (a Authentication) String() string {
	return fmt.Sprintf("session.Authentication{Name: %q, Authenticated: %t, Authorities: %q}", a.Name(), a.authed, a.authorities)
}

// Format implements fmt.Formatter like String, for every verb: fmt would
// otherwise print the principal's fields (an application's user record).
func (a Authentication) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, a.String()) }

// LogValue implements slog.LogValuer like String.
func (a Authentication) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("name", a.Name()),
		slog.Bool("authenticated", a.authed),
		slog.Any("authorities", a.authorities),
	)
}
