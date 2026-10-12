// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strconv"
)

// redactedKey stands for key material wherever a key is printed, logged
// or encoded.
const redactedKey = "REDACTED"

// keyJSON is the encoding/json form of a key whose material is redacted.
type keyJSON struct {
	KeyID     string
	Algorithm Algorithm
	Key       string
}

// formatKey implements fmt.Formatter for the types that hold keys: every
// verb prints their redacted String. Without it, fmt prints their fields
// for the verbs String does not cover (%d, %t…) — and, for the values
// held in unexported fields, for every verb, as it cannot call their
// methods. fmt handles %p of a non-pointer value before any method: no
// type can redact that one.
func formatKey(f fmt.State, s fmt.Stringer) { _, _ = io.WriteString(f, s.String()) }

// String implements fmt.Stringer with the key's identifiers and type: the
// key material is never printed.
func (k PrivateKey) String() string {
	return fmt.Sprintf("jwtsec.PrivateKey{KeyID: %q, Algorithm: %s, Key: %T %s}", k.KeyID, k.Algorithm, k.Key, redactedKey)
}

// Format implements fmt.Formatter like String, for every verb, %#v
// included: without it, fmt prints the material of a key held by value —
// an Ed25519 or HMAC key — for most verbs.
func (k PrivateKey) Format(f fmt.State, _ rune) { formatKey(f, k) }

// LogValue implements slog.LogValuer with the key's identifiers and type.
func (k PrivateKey) LogValue() slog.Value {
	return slog.GroupValue(slog.String("kid", k.KeyID), slog.String("alg", string(k.Algorithm)),
		slog.String("key", fmt.Sprintf("%T %s", k.Key, redactedKey)))
}

// MarshalJSON implements json.Marshaler without the key material:
// encoding/json would otherwise write the private key's fields — a
// configuration holding keys, logged as JSON, would reveal them.
func (k PrivateKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(keyJSON{KeyID: k.KeyID, Algorithm: k.Algorithm, Key: fmt.Sprintf("%T %s", k.Key, redactedKey)}) //nolint:wrapcheck // strings only: never fails
}

// symmetric reports whether the verification key is a shared secret (HMAC).
func (k PublicKey) symmetric() bool {
	_, ok := k.Key.([]byte)

	return ok
}

// String implements fmt.Stringer with the key's identifiers and type; the
// material of a symmetric (HMAC) key, which is a secret, is redacted.
func (k PublicKey) String() string {
	suffix := ""
	if k.symmetric() {
		suffix = " " + redactedKey
	}

	return fmt.Sprintf("jwtsec.PublicKey{KeyID: %q, Algorithm: %s, Key: %T%s}", k.KeyID, k.Algorithm, k.Key, suffix)
}

// Format implements fmt.Formatter like String, for every verb, %#v
// included.
func (k PublicKey) Format(f fmt.State, _ rune) { formatKey(f, k) }

// LogValue implements slog.LogValuer with the key's identifiers and type.
func (k PublicKey) LogValue() slog.Value {
	return slog.GroupValue(slog.String("kid", k.KeyID), slog.String("alg", string(k.Algorithm)),
		slog.String("key", fmt.Sprintf("%T", k.Key)))
}

// MarshalJSON implements json.Marshaler: the default encoding for an
// asymmetric key — public material — and a redacted one for a symmetric
// (HMAC) key.
func (k PublicKey) MarshalJSON() ([]byte, error) {
	if k.symmetric() {
		return json.Marshal(keyJSON{KeyID: k.KeyID, Algorithm: k.Algorithm, Key: fmt.Sprintf("%T %s", k.Key, redactedKey)}) //nolint:wrapcheck // strings only: never fails
	}

	type plain PublicKey

	return json.Marshal(plain(k)) //nolint:wrapcheck // the default encoding, its own error
}

// String implements fmt.Stringer with the signer's key identifiers and
// token type: the key material is never printed.
func (s *signer) String() string {
	return fmt.Sprintf("jwtsec.Signer{KeyID: %q, Algorithm: %s, Type: %q}", s.key.KeyID, s.key.Algorithm, s.typ)
}

// Format implements fmt.Formatter like String, for every verb.
func (s *signer) Format(f fmt.State, _ rune) { formatKey(f, s) }

// String implements fmt.Stringer with the signer's key identifiers: the key
// material is never printed.
func (s *OAuth2AccessTokenSigner) String() string {
	return fmt.Sprintf("jwtsec.OAuth2AccessTokenSigner{%v}", s.signer)
}

// Format implements fmt.Formatter like String, for every verb.
func (s *OAuth2AccessTokenSigner) Format(f fmt.State, _ rune) { formatKey(f, s) }

// String implements fmt.Stringer with the key IDs of the set and of its
// active signing key: no key material is printed.
func (s *staticKeySet) String() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := make([]string, 0, len(s.publics))
	for _, k := range s.publics {
		ids = append(ids, k.KeyID)
	}

	active := "none"
	if s.active != nil {
		active = strconv.Quote(s.active.KeyID)
	}

	return fmt.Sprintf("jwtsec.KeySet{KeyIDs: %q, Active: %s}", ids, active)
}

// Format implements fmt.Formatter like String, for every verb.
func (s *staticKeySet) Format(f fmt.State, _ rune) { formatKey(f, s) }

// String implements fmt.Stringer like the String of its key set.
func (p staticProvider) String() string { return "jwtsec.StaticJWKS{" + p.set.String() + "}" }

// Format implements fmt.Formatter like String, for every verb.
func (p staticProvider) Format(f fmt.State, _ rune) { formatKey(f, p) }

// String implements fmt.Stringer with the verifier's expectations and the
// type of its key provider, never the keys.
func (v *verifier) String() string {
	return fmt.Sprintf("jwtsec.Verifier{Provider: %T, Issuer: %q, Audience: %q, Type: %q}", v.provider, v.cfg.issuer, v.cfg.audiences, v.cfg.typ)
}

// Format implements fmt.Formatter like String, for every verb.
func (v *verifier) Format(f fmt.State, _ rune) { formatKey(f, v) }
