// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// MinKeySize is the minimum size of a session key, in bytes: 32 bytes from
// a cryptographic random source, never a passphrase.
const MinKeySize = 32

// cookieFormat is the version of the cookie format, written in clear as the
// first byte of every cookie and bound into the AEAD associated data. The
// unversioned format before it — SHA-256(key), no associated data — is
// version 1 and no longer opens.
const cookieFormat byte = 2

// keyLabel is the HKDF info that derives the AES-256-GCM key of a cookie
// key, so that a secret reused elsewhere never yields the same AES key.
const keyLabel = "github.com/hyperscale-stack/security/session v2 AES-256-GCM"

// Codec seals a [Session] into an opaque cookie value and opens it back. It
// holds the AES-256-GCM ciphers of the session keys; only the [Manager]
// seals and opens cookies, always bound to its cookie name and purpose.
//
// Cookie format v2:
//
//	value = base64url(0x02 ‖ nonce(12) ‖ AES-256-GCM_k(nonce, payload, AD))
//	k     = HKDF-SHA256(key, salt = ∅, info = "github.com/hyperscale-stack/security/session v2 AES-256-GCM")
//	AD    = 0x02 ‖ uint16be(len(name)) ‖ name ‖ uint16be(len(purpose)) ‖ purpose
//
// GCM is an AEAD construction: a single pass provides confidentiality and
// integrity, and the associated data binds the cookie to the format version,
// the cookie name and the purpose ([WithPurpose]) — a cookie sealed for
// another name or purpose fails the tag check (NIST SP 800-38D).
//
// Codec supports key rotation. The first key is the ACTIVE key, used to
// seal; every key is tried on open, so an operator can prepend a new key
// and keep opening cookies sealed with the previous one.
//
// Nonces are random (96 bits): NIST SP 800-38D §8.3 caps the number of
// seals under one key at 2^32. Every Login, Touch and Rotate is one seal:
// rotate the active key before that volume (about 50 days at 1 000 cookie
// writes per second), and do not Touch on every request.
type Codec struct {
	aeads []cipher.AEAD
}

// ErrInvalidKeys is returned by [NewCodec] when no key is supplied or a key
// is not a random key of at least [MinKeySize] bytes.
var ErrInvalidKeys = errors.New("session: at least one key of at least 32 random bytes is required")

// ErrDecode is returned (wrapped in [ErrNoSession]) when a cookie value
// cannot be opened with any configured key for the Manager's cookie name and
// purpose (tampering, retired key, another cookie, previous format,
// garbage).
var ErrDecode = errors.New("session: cookie could not be decoded")

// NewCodec builds a [Codec] from one or more keys. keys[0] seals new
// cookies; every key opens them (rotation). Each key MUST be at least
// [MinKeySize] bytes drawn from a cryptographic random source — generate one
// with `openssl rand -base64 32` and decode it, or crypto/rand — and is kept
// in a secret store, never in code or logs. A missing or shorter key, or one
// that repeats a single byte (a buffer never filled), fails with
// [ErrInvalidKeys]; randomness cannot otherwise be checked. The error names
// the key's position and size, never its bytes. Keys are expanded with
// HKDF-SHA256 (RFC 5869).
func NewCodec(keys ...[]byte) (*Codec, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: no key", ErrInvalidKeys)
	}

	aeads := make([]cipher.AEAD, 0, len(keys))

	for i, k := range keys {
		if len(k) < MinKeySize {
			return nil, fmt.Errorf("%w: key %d is %d bytes", ErrInvalidKeys, i, len(k))
		}

		if bytes.Count(k, k[:1]) == len(k) {
			return nil, fmt.Errorf("%w: key %d repeats a single byte", ErrInvalidKeys, i)
		}

		derived, err := hkdf.Key(sha256.New, k, nil, keyLabel, 32)
		if err != nil {
			return nil, fmt.Errorf("session: derive key: %w", err)
		}

		block, err := aes.NewCipher(derived)
		if err != nil {
			return nil, fmt.Errorf("session: build cipher: %w", err)
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("session: build GCM: %w", err)
		}

		aeads = append(aeads, gcm)
	}

	return &Codec{aeads: aeads}, nil
}

// String implements fmt.Stringer with the number of keys: the keys, and the
// ciphers built from them, are never printed.
func (c *Codec) String() string { return fmt.Sprintf("session.Codec{Keys: %d}", len(c.aeads)) }

// Format implements fmt.Formatter like String, for every verb: without it,
// fmt prints the AES key schedule behind the ciphers — which starts with
// the encryption key — for the verbs a pointer does not take (%s, %q…).
// fmt handles %p of a non-pointer value before any method: no type can
// redact that one.
func (c *Codec) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, c.String()) }

// payload is the sealed form of a Session: short field names keep the
// cookie small, and the redacting MarshalJSON of Session never applies.
type payload struct {
	ID           string         `json:"id"`
	Values       map[string]any `json:"v,omitempty"`
	CSRFToken    string         `json:"csrf"`
	CreatedAt    time.Time      `json:"c"`
	LastAccessed time.Time      `json:"a"`
	ExpiresAt    time.Time      `json:"e"`
}

// associatedData binds a cookie to the format version, the cookie name and
// the purpose; the length prefixes make it unambiguous. The Manager bounds
// both lengths (cookie names are tokens of at most 256 bytes, purposes at
// most 255 bytes).
func associatedData(name, purpose string) []byte {
	ad := make([]byte, 0, 5+len(name)+len(purpose))
	ad = append(ad, cookieFormat)
	ad = binary.BigEndian.AppendUint16(ad, uint16(len(name))) //nolint:gosec // G115: bounded by the Manager
	ad = append(ad, name...)
	ad = binary.BigEndian.AppendUint16(ad, uint16(len(purpose))) //nolint:gosec // G115: bounded by the Manager

	return append(ad, purpose...)
}

// seal serializes s and seals it with the active key for the cookie name
// and purpose.
func (c *Codec) seal(s *Session, name, purpose string) (string, error) {
	plaintext, err := json.Marshal(payload{
		ID: s.ID, Values: s.Values, CSRFToken: s.CSRFToken,
		CreatedAt: s.CreatedAt, LastAccessed: s.LastAccessed, ExpiresAt: s.ExpiresAt,
	})
	if err != nil {
		return "", fmt.Errorf("session: marshal: %w", err)
	}

	active := c.aeads[0]

	nonce := make([]byte, active.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("session: read nonce: %w", err)
	}

	out := make([]byte, 0, 1+len(nonce)+len(plaintext)+active.Overhead())
	out = append(out, cookieFormat)
	out = append(out, nonce...)
	out = active.Seal(out, nonce, plaintext, associatedData(name, purpose))

	return base64.RawURLEncoding.EncodeToString(out), nil
}

// open reverses seal for the cookie name and purpose, trying every key so
// that a cookie sealed before a key rotation still opens. Any failure (too
// long, bad base64, another version, wrong key or binding, tampered
// ciphertext, bad payload) collapses to ErrDecode — the caller MUST NOT
// distinguish the causes (a padding-oracle-style information leak).
func (c *Codec) open(value, name, purpose string) (*Session, error) {
	if len(value) > MaxCookieSize {
		return nil, ErrDecode
	}

	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, ErrDecode
	}

	// Every key is AES-256-GCM: same nonce size and overhead.
	ns := c.aeads[0].NonceSize()
	if len(raw) < 1+ns+c.aeads[0].Overhead() || raw[0] != cookieFormat {
		return nil, ErrDecode
	}

	nonce, ciphertext, ad := raw[1:1+ns], raw[1+ns:], associatedData(name, purpose)

	for _, aead := range c.aeads {
		plaintext, err := aead.Open(nil, nonce, ciphertext, ad)
		if err != nil {
			continue // wrong key, binding or tampered — try the next key
		}

		return decodePayload(plaintext)
	}

	return nil, ErrDecode
}

// decodePayload decodes a payload. Numbers decode as json.Number: integers
// beyond ±2^53 keep their precision (RFC 8259 §6).
func decodePayload(plaintext []byte) (*Session, error) {
	dec := json.NewDecoder(bytes.NewReader(plaintext))
	dec.UseNumber()

	var p payload
	if err := dec.Decode(&p); err != nil {
		return nil, ErrDecode
	}

	if p.Values == nil {
		p.Values = map[string]any{}
	}

	return &Session{
		ID: p.ID, Values: p.Values, CSRFToken: p.CSRFToken,
		CreatedAt: p.CreatedAt, LastAccessed: p.LastAccessed, ExpiresAt: p.ExpiresAt,
	}, nil
}
