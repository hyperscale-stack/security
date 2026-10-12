// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package password

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Bounds of the argon2id salt and tag (output) lengths, in bytes, for the
// hasher's own parameters and for every stored hash. They are library
// policy: RFC 9106 §3.1 only requires a tag of at least 4 bytes, and §4
// calls 128-bit salts and tags sufficient. A shorter tag lets random
// passwords verify (a 1-byte tag accepts about one in 256), a longer one
// buys nothing.
const (
	minArgon2idSaltLen = 16
	maxArgon2idSaltLen = 64
	minArgon2idKeyLen  = 16
	maxArgon2idKeyLen  = 64
	// maxArgon2idHashLen bounds the encoded hash: the longest valid one —
	// maximal parameters, 64-byte salt and tag — is 220 bytes.
	maxArgon2idHashLen = 256
)

// Argon2idParams configures Argon2id. Values follow the PHC string format
// (memory in KiB, time in iterations, parallelism in threads).
//
// The default profile (see [DefaultArgon2idParams]) is the minimum of the
// OWASP Password Storage Cheat Sheet: memory=19 MiB, time=2,
// parallelism=1, key length 32 bytes, salt length 16 bytes (~40 ms on a
// contemporary core). RFC 9106 §4 recommends stronger options — 2 GiB, t=1,
// p=4, or 64 MiB, t=3, p=4 when memory is scarce: raise the parameters
// towards them when the hardware allows (and the stored hashes follow
// through NeedsRehash).
type Argon2idParams struct {
	// MemoryKiB is the memory cost in kibibytes. Higher values strengthen
	// the hash against GPU/ASIC attacks but slow login down proportionally.
	// It MUST be at least 8×Parallelism (RFC 9106 §3.1).
	MemoryKiB uint32
	// Time is the iteration count (at least 1).
	Time uint32
	// Parallelism is the lane count (at least 1).
	Parallelism uint8
	// KeyLen is the output (tag) length in bytes: 16 to 64.
	KeyLen uint32
	// SaltLen is the salt length in bytes: 16 to 64. The salt is generated
	// with crypto/rand on every Hash call.
	SaltLen uint32
}

// DefaultArgon2idParams returns the OWASP Password Storage Cheat Sheet
// minimum profile (19 MiB, t=2, p=1, 32-byte key, 16-byte salt). Operators
// free to harden it for their threat model via NewArgon2idHasher.
func DefaultArgon2idParams() Argon2idParams {
	return Argon2idParams{
		MemoryKiB:   19 * 1024, // 19 MiB
		Time:        2,
		Parallelism: 1,
		KeyLen:      32,
		SaltLen:     16,
	}
}

// Argon2idLimits bounds the cost Verify accepts from a stored hash. It is
// checked before any hashing: an attacker able to write or import a hash
// could otherwise make each verification allocate gigabytes or run for
// hours. A stored hash above a limit fails with [ErrCostLimitExceeded].
// The limits are inclusive.
type Argon2idLimits struct {
	// MaxMemoryKiB bounds the stored memory cost. Default: 256 MiB.
	MaxMemoryKiB uint32
	// MaxTime bounds the stored iteration count. Default: 10.
	MaxTime uint32
	// MaxParallelism bounds the stored lane count. Default: 16.
	MaxParallelism uint8
}

// DefaultArgon2idLimits returns the default limits: 256 MiB, 10 passes and
// 16 lanes. They accept the OWASP profiles, RFC 9106 §4's second option
// (64 MiB, t=3, p=4), libsodium's interactive and moderate profiles and the
// PHP, Spring Security and Keycloak defaults; hashes made with 1 GiB or
// more (RFC 9106 §4's first option, libsodium's sensitive profile) need
// [WithArgon2idLimits].
func DefaultArgon2idLimits() Argon2idLimits {
	return Argon2idLimits{MaxMemoryKiB: 256 * 1024, MaxTime: 10, MaxParallelism: 16}
}

// withDefaults replaces the zero fields of l with the default limits.
func (l Argon2idLimits) withDefaults() Argon2idLimits {
	d := DefaultArgon2idLimits()

	if l.MaxMemoryKiB == 0 {
		l.MaxMemoryKiB = d.MaxMemoryKiB
	}

	if l.MaxTime == 0 {
		l.MaxTime = d.MaxTime
	}

	if l.MaxParallelism == 0 {
		l.MaxParallelism = d.MaxParallelism
	}

	return l
}

// Argon2idOption configures an [Argon2idHasher].
type Argon2idOption func(*Argon2idHasher)

// WithArgon2idLimits sets the limits Verify applies to stored hashes. A zero
// field keeps its default value, and every limit is raised to the hasher's
// own parameter: a hasher always verifies the hashes it produces.
func WithArgon2idLimits(l Argon2idLimits) Argon2idOption {
	return func(h *Argon2idHasher) { h.limits = l }
}

// Argon2idHasher implements [Hasher] using Argon2id from
// golang.org/x/crypto/argon2.
type Argon2idHasher struct {
	params Argon2idParams
	limits Argon2idLimits
}

// NewArgon2idHasher returns a [Hasher] configured with params. Zero-valued
// fields are replaced with [DefaultArgon2idParams] equivalents to keep the
// hasher usable from `&Argon2idHasher{}` without surprising silent zeroes.
// The limits default to [DefaultArgon2idLimits] (see [WithArgon2idLimits]).
//
// NewArgon2idHasher panics on parameters outside their bounds — a memory
// cost below 8×Parallelism (RFC 9106 §3.1), a key or salt length outside
// 16–64 bytes: they are static configuration, refused at start-up.
func NewArgon2idHasher(params Argon2idParams, opts ...Argon2idOption) *Argon2idHasher {
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

	if err := checkArgon2idParams(params); err != nil {
		panic("password: NewArgon2idHasher: " + err.Error())
	}

	h := &Argon2idHasher{params: params}

	for _, o := range opts {
		o(h)
	}

	h.limits = h.limits.withDefaults()
	h.limits.MaxMemoryKiB = max(h.limits.MaxMemoryKiB, params.MemoryKiB)
	h.limits.MaxTime = max(h.limits.MaxTime, params.Time)
	h.limits.MaxParallelism = max(h.limits.MaxParallelism, params.Parallelism)

	return h
}

// checkArgon2idParams checks the bounds shared by the hasher's parameters
// and the stored hashes: RFC 9106 §3.1 (t ≥ 1, p ≥ 1, m ≥ 8p) and the salt
// and key lengths.
func checkArgon2idParams(p Argon2idParams) error {
	switch {
	case p.Time < 1:
		return fmt.Errorf("time %d below 1 (RFC 9106 §3.1)", p.Time)
	case p.Parallelism < 1:
		return fmt.Errorf("parallelism %d below 1 (RFC 9106 §3.1)", p.Parallelism)
	case uint64(p.MemoryKiB) < 8*uint64(p.Parallelism):
		return fmt.Errorf("memory %d KiB below 8×parallelism (RFC 9106 §3.1)", p.MemoryKiB)
	case p.KeyLen < minArgon2idKeyLen || p.KeyLen > maxArgon2idKeyLen:
		return fmt.Errorf("key length %d outside %d–%d bytes", p.KeyLen, minArgon2idKeyLen, maxArgon2idKeyLen)
	case p.SaltLen < minArgon2idSaltLen || p.SaltLen > maxArgon2idSaltLen:
		return fmt.Errorf("salt length %d outside %d–%d bytes", p.SaltLen, minArgon2idSaltLen, maxArgon2idSaltLen)
	}

	return nil
}

// Params returns the hasher's effective parameters. Useful in tests and for
// observability.
func (h *Argon2idHasher) Params() Argon2idParams { return h.params }

// Limits returns the hasher's effective limits on stored hashes.
func (h *Argon2idHasher) Limits() Argon2idLimits { return h.limits }

// Hash implements [Hasher]. The output follows the PHC string format:
//
//	$argon2id$v=19$m=<KiB>,t=<iter>,p=<threads>$<base64salt>$<base64hash>
//
// The format is interoperable with libsodium, OpenSSH, and most modern
// argon2id implementations. An empty password is refused
// ([ErrEmptyPassword]).
func (h *Argon2idHasher) Hash(ctx context.Context, password string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("password: context canceled: %w", err)
	}

	if password == "" {
		return "", ErrEmptyPassword
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

// Verify implements [Hasher]. The stored hash is decoded and checked —
// RFC 9106 §3.1 bounds, salt and tag lengths, then the limits — before any
// hashing. It returns (false, nil) on a plain mismatch and for an empty
// password.
func (h *Argon2idHasher) Verify(ctx context.Context, encodedHash, password string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("password: context canceled: %w", err)
	}

	p, salt, expected, err := h.decode(encodedHash)
	if err != nil {
		return false, err
	}

	if password == "" {
		return false, nil
	}

	got := argon2.IDKey([]byte(password), salt, p.Time, p.MemoryKiB, p.Parallelism, p.KeyLen)

	return subtle.ConstantTimeCompare(expected, got) == 1, nil
}

// NeedsRehash implements [Hasher]: true when the stored hash cannot be
// verified (another algorithm, malformed, above the limits) or when any of
// its parameters — memory, passes, lanes, tag or salt length — is weaker
// than the current configuration.
func (h *Argon2idHasher) NeedsRehash(encodedHash string) bool {
	p, _, _, err := h.decode(encodedHash)
	if err != nil {
		return true
	}

	return p.MemoryKiB < h.params.MemoryKiB ||
		p.Time < h.params.Time ||
		p.Parallelism < h.params.Parallelism ||
		p.KeyLen < h.params.KeyLen ||
		p.SaltLen < h.params.SaltLen
}

// decode parses encodedHash and applies the bounds and the limits.
func (h *Argon2idHasher) decode(encodedHash string) (Argon2idParams, []byte, []byte, error) {
	p, salt, key, err := decodeArgon2idPHC(encodedHash)
	if err != nil {
		return Argon2idParams{}, nil, nil, err
	}

	if p.MemoryKiB > h.limits.MaxMemoryKiB || p.Time > h.limits.MaxTime || p.Parallelism > h.limits.MaxParallelism {
		return Argon2idParams{}, nil, nil, fmt.Errorf("%w: m=%d,t=%d,p=%d", ErrCostLimitExceeded, p.MemoryKiB, p.Time, p.Parallelism)
	}

	return p, salt, key, nil
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

// decodeArgon2idPHC parses a PHC-formatted argon2id hash and checks its
// bounds: version 19, each of m, t and p exactly once (in any order) and
// nothing else, RFC 9106 §3.1 ranges, salt and tag of 16 to 64 bytes. The
// algorithm is checked first so that cross-algorithm inputs (bcrypt,
// scrypt) get a clear ErrUnsupportedAlgorithm.
func decodeArgon2idPHC(s string) (Argon2idParams, []byte, []byte, error) {
	rest, ok := strings.CutPrefix(s, "$")
	if !ok {
		return Argon2idParams{}, nil, nil, ErrMalformedHash
	}

	if alg, _, _ := strings.Cut(rest, "$"); alg != "argon2id" {
		return Argon2idParams{}, nil, nil, ErrUnsupportedAlgorithm
	}

	// Bounded before it is split: a hostile hash costs no allocation.
	if len(s) > maxArgon2idHashLen {
		return Argon2idParams{}, nil, nil, ErrMalformedHash
	}

	// Expected layout: ["", "argon2id", "v=19", "m=...,t=...,p=...", salt, key]
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[2] != "v=19" {
		return Argon2idParams{}, nil, nil, ErrMalformedHash
	}

	p, err := parseArgon2idParams(parts[3])
	if err != nil {
		return Argon2idParams{}, nil, nil, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return Argon2idParams{}, nil, nil, ErrMalformedHash
	}

	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return Argon2idParams{}, nil, nil, ErrMalformedHash
	}

	// Both lengths are bounded by the 256-byte encoding checked above.
	p.KeyLen = uint32(len(key))   //nolint:gosec // G115: at most 192 bytes
	p.SaltLen = uint32(len(salt)) //nolint:gosec // G115: at most 192 bytes

	if checkArgon2idParams(p) != nil {
		return Argon2idParams{}, nil, nil, ErrMalformedHash
	}

	return p, salt, key, nil
}

// parseArgon2idParams parses the "m=…,t=…,p=…" field: each parameter
// exactly once, in any order, unsigned decimal, nothing else.
func parseArgon2idParams(field string) (Argon2idParams, error) {
	var (
		p    Argon2idParams
		seen [3]bool
	)

	for kv := range strings.SplitSeq(field, ",") {
		name, value, _ := strings.Cut(kv, "=")

		switch name {
		case "m":
			n, err := strconv.ParseUint(value, 10, 32)
			if err != nil || seen[0] {
				return Argon2idParams{}, ErrMalformedHash
			}

			seen[0], p.MemoryKiB = true, uint32(n)
		case "t":
			n, err := strconv.ParseUint(value, 10, 32)
			if err != nil || seen[1] {
				return Argon2idParams{}, ErrMalformedHash
			}

			seen[1], p.Time = true, uint32(n)
		case "p":
			n, err := strconv.ParseUint(value, 10, 8)
			if err != nil || seen[2] {
				return Argon2idParams{}, ErrMalformedHash
			}

			seen[2], p.Parallelism = true, uint8(n)
		default:
			return Argon2idParams{}, ErrMalformedHash
		}
	}

	if !seen[0] || !seen[1] || !seen[2] {
		return Argon2idParams{}, ErrMalformedHash
	}

	return p, nil
}
