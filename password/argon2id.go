// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package password

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2idParams configures Argon2id. Values follow the PHC string format
// (memory in KiB, time in iterations, parallelism in threads).
//
// The default profile (see [DefaultArgon2idParams]) is RFC 9106 §4 / OWASP
// 2024: memory=19 MiB, time=2, parallelism=1, key length 32 bytes, salt
// length 16 bytes. This profile aims at ~50 ms on a contemporary x86 core.
type Argon2idParams struct {
	// MemoryKiB is the memory cost in kibibytes. Higher values strengthen
	// the hash against GPU/ASIC attacks but slow login down proportionally.
	MemoryKiB uint32
	// Time is the iteration count.
	Time uint32
	// Parallelism is the lane count.
	Parallelism uint8
	// KeyLen is the output length in bytes.
	KeyLen uint32
	// SaltLen is the salt length in bytes. The salt is generated with
	// crypto/rand on every Hash call.
	SaltLen uint32
}

// DefaultArgon2idParams returns the OWASP 2024 / RFC 9106 §4 profile.
// Operators free to harden it for their threat model via NewArgon2idHasher.
func DefaultArgon2idParams() Argon2idParams {
	return Argon2idParams{
		MemoryKiB:   19 * 1024, // 19 MiB
		Time:        2,
		Parallelism: 1,
		KeyLen:      32,
		SaltLen:     16,
	}
}

// Argon2idHasher implements [Hasher] using Argon2id from
// golang.org/x/crypto/argon2.
type Argon2idHasher struct {
	params Argon2idParams
}

// NewArgon2idHasher returns a [Hasher] configured with params. Zero-valued
// fields are replaced with [DefaultArgon2idParams] equivalents to keep the
// hasher usable from `&Argon2idHasher{}` without surprising silent zeroes.
func NewArgon2idHasher(params Argon2idParams) *Argon2idHasher {
	d := DefaultArgon2idParams()

	if params.MemoryKiB == 0 {
		params.MemoryKiB = d.MemoryKiB
	}

	if params.Time == 0 {
		params.Time = d.Time
	}

	if params.Parallelism == 0 {
		params.Parallelism = d.Parallelism
	}

	if params.KeyLen == 0 {
		params.KeyLen = d.KeyLen
	}

	if params.SaltLen == 0 {
		params.SaltLen = d.SaltLen
	}

	return &Argon2idHasher{params: params}
}

// Params returns the hasher's effective parameters. Useful in tests and for
// observability.
func (h *Argon2idHasher) Params() Argon2idParams { return h.params }

// Hash implements [Hasher]. The output follows the PHC string format:
//
//	$argon2id$v=19$m=<KiB>,t=<iter>,p=<threads>$<base64salt>$<base64hash>
//
// The format is interoperable with libsodium, OpenSSH, and most modern
// argon2id implementations.
func (h *Argon2idHasher) Hash(ctx context.Context, password string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("password: context canceled: %w", err)
	}

	salt := make([]byte, h.params.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password: read salt: %w", err)
	}

	key := argon2.IDKey(
		[]byte(password), salt,
		h.params.Time, h.params.MemoryKiB, h.params.Parallelism, h.params.KeyLen,
	)

	return encodeArgon2idPHC(h.params, salt, key), nil
}

// Verify implements [Hasher]. It returns (false, nil) on plain mismatch and
// an error only when the hash is malformed or the algorithm prefix differs.
func (h *Argon2idHasher) Verify(ctx context.Context, encodedHash, password string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("password: context canceled: %w", err)
	}

	p, salt, expected, err := decodeArgon2idPHC(encodedHash)
	if err != nil {
		return false, err
	}

	got := argon2.IDKey([]byte(password), salt, p.Time, p.MemoryKiB, p.Parallelism, p.KeyLen)

	if subtle.ConstantTimeCompare(expected, got) == 1 {
		return true, nil
	}

	return false, nil
}

// NeedsRehash implements [Hasher]: true when the algorithm is not argon2id
// or when any stored parameter is strictly weaker than the current
// configuration.
func (h *Argon2idHasher) NeedsRehash(encodedHash string) bool {
	p, _, _, err := decodeArgon2idPHC(encodedHash)
	if err != nil {
		return true
	}

	return p.MemoryKiB < h.params.MemoryKiB ||
		p.Time < h.params.Time ||
		p.Parallelism < h.params.Parallelism ||
		p.KeyLen < h.params.KeyLen
}

// encodeArgon2idPHC formats the parameters, salt and key in the PHC string
// format. base64 padding is intentionally stripped (PHC convention).
func encodeArgon2idPHC(p Argon2idParams, salt, key []byte) string {
	enc := base64.RawStdEncoding

	var b strings.Builder

	b.Grow(96)
	b.WriteString("$argon2id$v=")
	b.WriteString(strconv.Itoa(argon2.Version))
	b.WriteString("$m=")
	b.WriteString(strconv.FormatUint(uint64(p.MemoryKiB), 10))
	b.WriteString(",t=")
	b.WriteString(strconv.FormatUint(uint64(p.Time), 10))
	b.WriteString(",p=")
	b.WriteString(strconv.FormatUint(uint64(p.Parallelism), 10))
	b.WriteByte('$')
	b.WriteString(enc.EncodeToString(salt))
	b.WriteByte('$')
	b.WriteString(enc.EncodeToString(key))

	return b.String()
}

// decodeArgon2idPHC parses a PHC-formatted argon2id hash. Strict on prefix
// and field shape; tolerant of base64 padding to interop with implementations
// that emit RawStdEncoding output.
func decodeArgon2idPHC(s string) (Argon2idParams, []byte, []byte, error) {
	parts := strings.Split(s, "$")
	// Expected layout: ["", "argon2id", "v=19", "m=...,t=...,p=...", salt, key]
	// Algorithm check first so cross-algorithm inputs (bcrypt, scrypt) get a
	// clear ErrUnsupportedAlgorithm even when their layout has fewer fields.
	if len(parts) < 2 {
		return Argon2idParams{}, nil, nil, ErrMalformedHash
	}

	if parts[1] != "argon2id" {
		return Argon2idParams{}, nil, nil, ErrUnsupportedAlgorithm
	}

	if len(parts) != 6 {
		return Argon2idParams{}, nil, nil, ErrMalformedHash
	}

	if !strings.HasPrefix(parts[2], "v=") {
		return Argon2idParams{}, nil, nil, ErrMalformedHash
	}

	version, err := strconv.Atoi(parts[2][2:])
	if err != nil || version != argon2.Version {
		return Argon2idParams{}, nil, nil, ErrMalformedHash
	}

	var (
		mem, tim uint64
		par      uint64
	)

	for _, kv := range strings.Split(parts[3], ",") {
		switch {
		case strings.HasPrefix(kv, "m="):
			mem, err = strconv.ParseUint(kv[2:], 10, 32)
		case strings.HasPrefix(kv, "t="):
			tim, err = strconv.ParseUint(kv[2:], 10, 32)
		case strings.HasPrefix(kv, "p="):
			par, err = strconv.ParseUint(kv[2:], 10, 8)
		default:
			err = errors.New("unknown key")
		}

		if err != nil {
			return Argon2idParams{}, nil, nil, ErrMalformedHash
		}
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return Argon2idParams{}, nil, nil, ErrMalformedHash
	}

	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return Argon2idParams{}, nil, nil, ErrMalformedHash
	}

	// len() on a decoded base64 string is bounded by the input length
	// (a few hundred bytes at most for a sane hash). The uint32 conversion
	// cannot overflow in practice — gosec's static analyser cannot prove
	// that, hence the explicit annotation.
	return Argon2idParams{
		MemoryKiB:   uint32(mem),
		Time:        uint32(tim),
		Parallelism: uint8(par),
		KeyLen:      uint32(len(key)),  //nolint:gosec // bounded by base64 of <= 64-byte key
		SaltLen:     uint32(len(salt)), //nolint:gosec // bounded by base64 of <= 64-byte salt
	}, salt, key, nil
}
