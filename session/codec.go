// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// Codec encrypts and authenticates a [Session] into an opaque cookie value
// and back. It uses AES-256-GCM: GCM is an AEAD construction, so a single
// pass provides BOTH confidentiality and integrity — no separate HMAC is
// needed (a tampered ciphertext fails the GCM tag check on Open).
//
// Codec supports key rotation. The first key is the ACTIVE key, used to
// encrypt; every key is tried on decrypt, so an operator can prepend a new
// key and keep decoding cookies sealed with the previous one. Each input
// key is run through SHA-256 so keys of any length yield a valid 32-byte
// AES-256 key.
type Codec struct {
	aeads []cipher.AEAD
}

// ErrInvalidKeys is returned by [NewCodec] when no key is supplied.
var ErrInvalidKeys = errors.New("session: at least one encryption key is required")

// ErrDecode is returned by [Codec.Decode] when the cookie value cannot be
// authenticated with any configured key (tampering, expired key, garbage).
var ErrDecode = errors.New("session: cookie could not be decoded")

// NewCodec builds a [Codec] from one or more raw key bytes. keys[0] is the
// active encryption key; the rest are decrypt-only (rotation). At least one
// key is mandatory.
func NewCodec(keys ...[]byte) (*Codec, error) {
	if len(keys) == 0 {
		return nil, ErrInvalidKeys
	}

	aeads := make([]cipher.AEAD, 0, len(keys))

	for _, k := range keys {
		derived := sha256.Sum256(k)

		block, err := aes.NewCipher(derived[:])
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

// Encode serializes s to JSON and seals it with the active key. The output
// is base64url(nonce || ciphertext||tag), safe for a cookie value.
func (c *Codec) Encode(s *Session) (string, error) {
	plaintext, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("session: marshal: %w", err)
	}

	active := c.aeads[0]

	nonce := make([]byte, active.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("session: read nonce: %w", err)
	}

	sealed := active.Seal(nonce, nonce, plaintext, nil)

	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// Decode reverses [Codec.Encode]. It tries every configured key so that a
// cookie sealed before a key rotation still opens. Any failure (bad
// base64, wrong key, tampered ciphertext) collapses to [ErrDecode] — the
// caller MUST NOT distinguish the causes (it would be a padding-oracle-
// style information leak).
func (c *Codec) Decode(value string) (*Session, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, ErrDecode
	}

	for _, aead := range c.aeads {
		ns := aead.NonceSize()
		if len(raw) < ns {
			continue
		}

		nonce, ciphertext := raw[:ns], raw[ns:]

		plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			continue // wrong key or tampered — try the next key
		}

		var s Session
		if err := json.Unmarshal(plaintext, &s); err != nil {
			return nil, ErrDecode
		}

		return &s, nil
	}

	return nil, ErrDecode
}
