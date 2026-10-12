// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package password_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/hyperscale-stack/security/password"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// phc encodes an argon2id hash with the given parameter field, salt and tag,
// the way a foreign system or a tampered store row could.
func phc(params string, salt, tag []byte) string {
	enc := base64.RawStdEncoding

	return "$argon2id$v=19$" + params + "$" + enc.EncodeToString(salt) + "$" + enc.EncodeToString(tag)
}

// realPHC hashes pw with x/crypto directly — the hash any argon2id
// implementation would store for these parameters.
func realPHC(pw string, m, t uint32, p uint8, saltLen, keyLen int) string {
	salt := bytes.Repeat([]byte{0x5a}, saltLen)
	tag := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(keyLen)) //nolint:gosec // test sizes

	return phc(fmt.Sprintf("m=%d,t=%d,p=%d", m, t, p), salt, tag)
}

// verifyNoPanic calls Verify and turns a panic into a test failure: before
// the bounds, a stored t=0, p=0 or empty tag panicked inside x/crypto.
func verifyNoPanic(t *testing.T, h password.Hasher, hash, pw string) (ok bool, err error) {
	t.Helper()

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Verify(%.60q) panicked: %v", hash, r)
		}
	}()

	return h.Verify(context.Background(), hash, pw)
}

// tinyLimits keeps every accepted stored hash cheap to verify.
func tinyLimitsHasher() *password.Argon2idHasher {
	return password.NewArgon2idHasher(
		password.Argon2idParams{MemoryKiB: 8, Time: 1, Parallelism: 1, KeyLen: 16, SaltLen: 16},
		password.WithArgon2idLimits(password.Argon2idLimits{MaxMemoryKiB: 64, MaxTime: 2, MaxParallelism: 2}),
	)
}

// Audit CORE-06 (probe TestZZAuditArgon2idStoredHashBounds): stored
// parameters were parsed without bounds — t=0, p=0 and a missing t panicked
// in x/crypto, an empty tag dereferenced nil, a 1-byte tag accepted about
// one random password in 256 and absurd costs were honored. RFC 9106 §3.1:
// t ≥ 1, p ≥ 1, m ≥ 8p; library policy: salt and tag of 16 to 64 bytes;
// operator limits on the cost. Every refusal happens before any hashing.
func TestArgon2idVerifyRefusesOutOfBoundsHashes(t *testing.T) {
	t.Parallel()

	salt := bytes.Repeat([]byte{1}, 16)
	tag := bytes.Repeat([]byte{2}, 32)

	cases := []struct {
		name string
		hash string
		want error
	}{
		{"t=0", phc("m=64,t=0,p=1", salt, tag), password.ErrMalformedHash},
		{"p=0", phc("m=64,t=1,p=0", salt, tag), password.ErrMalformedHash},
		{"m below 8p", phc("m=15,t=1,p=2", salt, tag), password.ErrMalformedHash},
		{"t and p missing", phc("m=64", salt, tag), password.ErrMalformedHash},
		{"p missing", phc("m=64,t=1", salt, tag), password.ErrMalformedHash},
		{"duplicate m", phc("m=64,t=1,p=1,m=8", salt, tag), password.ErrMalformedHash},
		{"duplicate t", phc("m=64,t=1,t=2,p=1", salt, tag), password.ErrMalformedHash},
		{"unknown parameter", phc("m=64,t=1,p=1,keyid=a", salt, tag), password.ErrMalformedHash},
		{"empty parameter", phc("m=64,,t=1,p=1", salt, tag), password.ErrMalformedHash},
		{"signed value", phc("m=+64,t=1,p=1", salt, tag), password.ErrMalformedHash},
		{"empty tag", phc("m=64,t=1,p=1", salt, nil), password.ErrMalformedHash},
		{"1-byte tag", phc("m=8,t=1,p=1", salt, []byte{0x42}), password.ErrMalformedHash},
		{"15-byte tag", phc("m=64,t=1,p=1", salt, tag[:15]), password.ErrMalformedHash},
		{"65-byte tag", phc("m=64,t=1,p=1", salt, bytes.Repeat([]byte{2}, 65)), password.ErrMalformedHash},
		{"empty salt", phc("m=64,t=1,p=1", nil, tag), password.ErrMalformedHash},
		{"15-byte salt", phc("m=64,t=1,p=1", salt[:15], tag), password.ErrMalformedHash},
		{"65-byte salt", phc("m=64,t=1,p=1", bytes.Repeat([]byte{1}, 65), tag), password.ErrMalformedHash},
		{"version 16", strings.Replace(phc("m=64,t=1,p=1", salt, tag), "v=19", "v=16", 1), password.ErrMalformedHash},
		{"no version", strings.Replace(phc("m=64,t=1,p=1", salt, tag), "$v=19", "", 1), password.ErrMalformedHash},
		{"extra field", phc("m=64,t=1,p=1", salt, tag) + "$x", password.ErrMalformedHash},
		{"too long", phc("m=64,t=1,p=1", salt, tag) + strings.Repeat("A", 200), password.ErrMalformedHash},
		{"memory above the limit", phc("m=65,t=1,p=1", salt, tag), password.ErrCostLimitExceeded},
		{"time above the limit", phc("m=64,t=3,p=1", salt, tag), password.ErrCostLimitExceeded},
		{"parallelism above the limit", phc("m=64,t=1,p=3", salt, tag), password.ErrCostLimitExceeded},
		{"maximal memory", phc("m=4294967295,t=1,p=1", salt, tag), password.ErrCostLimitExceeded},
		{"maximal time and lanes", phc("m=4294967295,t=4294967295,p=255", salt, tag), password.ErrCostLimitExceeded},
	}

	h := tinyLimitsHasher()

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			ok, err := verifyNoPanic(t, h, c.hash, "whatever")

			require.ErrorIs(t, err, c.want)
			assert.False(t, ok)
			assert.True(t, h.NeedsRehash(c.hash), "a hash Verify refuses always needs a rehash")
		})
	}
}

// The probe's 1-byte stored tag accepted 7 of 2000 random passwords.
func TestArgon2idVerifyNeverAcceptsAShortTag(t *testing.T) {
	t.Parallel()

	h := tinyLimitsHasher()
	hash := phc("m=8,t=1,p=1", bytes.Repeat([]byte{1}, 16), []byte{0x42})

	for i := range 600 {
		ok, _ := verifyNoPanic(t, h, hash, fmt.Sprintf("guess-%d", i))
		require.False(t, ok, "guess-%d accepted", i)
	}
}

// The limits are inclusive and default to 256 MiB, 10 passes and 16 lanes:
// libsodium's MODERATE profile (256 MiB, t=3) sits exactly on the memory
// limit. NeedsRehash tells an accepted hash (false: stronger than the
// configuration) from a refused one (true) without hashing.
func TestArgon2idDefaultLimitsAreInclusive(t *testing.T) {
	t.Parallel()

	h := password.NewArgon2idHasher(password.Argon2idParams{})
	salt := bytes.Repeat([]byte{1}, 16)
	tag := bytes.Repeat([]byte{2}, 32)

	assert.Equal(t, password.Argon2idLimits{MaxMemoryKiB: 256 * 1024, MaxTime: 10, MaxParallelism: 16}, password.DefaultArgon2idLimits())
	assert.Equal(t, password.DefaultArgon2idLimits(), h.Limits())

	for params, refused := range map[string]bool{
		"m=262144,t=2,p=1":  false,
		"m=262145,t=2,p=1":  true,
		"m=19456,t=10,p=1":  false,
		"m=19456,t=11,p=1":  true,
		"m=19456,t=2,p=16":  false,
		"m=19456,t=2,p=17":  true,
		"m=65536,t=3,p=2":   false, // infinityauth's profile
		"m=262144,t=3,p=4":  false, // libsodium MODERATE-like
		"m=1048576,t=4,p=1": true,  // libsodium SENSITIVE needs WithArgon2idLimits
	} {
		assert.Equal(t, refused, h.NeedsRehash(phc(params, salt, tag)), params)
	}

	_, err := verifyNoPanic(t, h, phc("m=262145,t=2,p=1", salt, tag), "x")
	require.ErrorIs(t, err, password.ErrCostLimitExceeded)
}

// A hasher always verifies its own hashes: the limits are raised to its
// parameters, whatever the option says.
func TestArgon2idLimitsNeverRefuseTheHashersOwnHashes(t *testing.T) {
	t.Parallel()

	h := password.NewArgon2idHasher(
		password.Argon2idParams{MemoryKiB: 128, Time: 3, Parallelism: 4, KeyLen: 16, SaltLen: 16},
		password.WithArgon2idLimits(password.Argon2idLimits{MaxMemoryKiB: 64, MaxTime: 1, MaxParallelism: 1}),
	)

	assert.Equal(t, password.Argon2idLimits{MaxMemoryKiB: 128, MaxTime: 3, MaxParallelism: 4}, h.Limits())

	hash, err := h.Hash(context.Background(), "pw")
	require.NoError(t, err)

	ok, err := verifyNoPanic(t, h, hash, "pw")
	require.NoError(t, err)
	assert.True(t, ok)

	// A zero limit takes its default value.
	partial := password.NewArgon2idHasher(password.Argon2idParams{},
		password.WithArgon2idLimits(password.Argon2idLimits{MaxMemoryKiB: 1 << 20}))
	assert.Equal(t, password.Argon2idLimits{MaxMemoryKiB: 1 << 20, MaxTime: 10, MaxParallelism: 16}, partial.Limits())
}

// Hashes of other argon2id implementations: every mainstream encoder emits
// m,t,p in that order; another order is accepted as long as each parameter
// appears exactly once.
func TestArgon2idVerifyAcceptsForeignHashes(t *testing.T) {
	t.Parallel()

	h := password.NewArgon2idHasher(password.Argon2idParams{},
		password.WithArgon2idLimits(password.Argon2idLimits{MaxMemoryKiB: 1024}))

	canonical := realPHC("correct horse", 1024, 3, 2, 16, 32)
	reordered := strings.Replace(canonical, "m=1024,t=3,p=2", "t=3,p=2,m=1024", 1)
	longSalt := realPHC("correct horse", 64, 1, 1, 64, 64)

	for name, hash := range map[string]string{"canonical": canonical, "reordered": reordered, "64-byte salt and tag": longSalt} {
		ok, err := verifyNoPanic(t, h, hash, "correct horse")
		require.NoError(t, err, name)
		assert.True(t, ok, name)

		ok, err = verifyNoPanic(t, h, hash, "wrong horse")
		require.NoError(t, err, name)
		assert.False(t, ok, name)
	}
}

// Audit §9 surviving mutant: the tag comparison reduced to its first byte.
func TestArgon2idVerifyComparesTheWholeTag(t *testing.T) {
	t.Parallel()

	h := tinyLimitsHasher()
	hash := realPHC("pw", 8, 1, 1, 16, 32)

	parts := strings.Split(hash, "$")
	tag, err := base64.RawStdEncoding.DecodeString(parts[5])
	require.NoError(t, err)

	tag[len(tag)-1] ^= 0x01
	parts[5] = base64.RawStdEncoding.EncodeToString(tag)

	ok, err := verifyNoPanic(t, h, strings.Join(parts, "$"), "pw")
	require.NoError(t, err)
	assert.False(t, ok, "a tag differing in its last byte must not verify")
}

// Audit §9 surviving mutant (NeedsRehash ignoring memory) and CORE-I7
// (NeedsRehash ignoring the salt length).
func TestArgon2idNeedsRehashOnEachWeakerParameter(t *testing.T) {
	t.Parallel()

	current := password.NewArgon2idHasher(password.Argon2idParams{MemoryKiB: 64, Time: 2, Parallelism: 2, KeyLen: 32, SaltLen: 32})

	for name, c := range map[string]struct {
		hash  string
		needs bool
	}{
		"same parameters":   {realPHC("x", 64, 2, 2, 32, 32), false},
		"stronger":          {realPHC("x", 128, 3, 4, 64, 64), false},
		"less memory only":  {realPHC("x", 32, 2, 2, 32, 32), true},
		"fewer passes only": {realPHC("x", 64, 1, 2, 32, 32), true},
		"fewer lanes only":  {realPHC("x", 64, 2, 1, 32, 32), true},
		"shorter tag only":  {realPHC("x", 64, 2, 2, 32, 16), true},
		"shorter salt only": {realPHC("x", 64, 2, 2, 16, 32), true},
	} {
		assert.Equal(t, c.needs, current.NeedsRehash(c.hash), name)
	}
}

// Audit CORE-06 (probe TestZZAuditArgon2idWeakConfigAccepted): the
// constructor accepted KeyLen=1 and SaltLen=1.
func TestNewArgon2idHasherRefusesOutOfRangeParameters(t *testing.T) {
	t.Parallel()

	base := func(mod func(*password.Argon2idParams)) password.Argon2idParams {
		p := password.Argon2idParams{MemoryKiB: 64, Time: 1, Parallelism: 1, KeyLen: 32, SaltLen: 16}
		mod(&p)

		return p
	}

	for name, p := range map[string]password.Argon2idParams{
		"1-byte tag":     base(func(p *password.Argon2idParams) { p.KeyLen = 1 }),
		"15-byte tag":    base(func(p *password.Argon2idParams) { p.KeyLen = 15 }),
		"65-byte tag":    base(func(p *password.Argon2idParams) { p.KeyLen = 65 }),
		"1-byte salt":    base(func(p *password.Argon2idParams) { p.SaltLen = 1 }),
		"15-byte salt":   base(func(p *password.Argon2idParams) { p.SaltLen = 15 }),
		"65-byte salt":   base(func(p *password.Argon2idParams) { p.SaltLen = 65 }),
		"m below 8p":     base(func(p *password.Argon2idParams) { p.MemoryKiB, p.Parallelism = 15, 2 }),
		"probe settings": {MemoryKiB: 8, Time: 1, KeyLen: 1, SaltLen: 1},
	} {
		assert.Panics(t, func() { password.NewArgon2idHasher(p) }, name)
	}

	for name, p := range map[string]password.Argon2idParams{
		"bounds":  base(func(p *password.Argon2idParams) { p.KeyLen, p.SaltLen = 16, 64 }),
		"upper":   base(func(p *password.Argon2idParams) { p.KeyLen, p.SaltLen = 64, 16 }),
		"m = 8p":  base(func(p *password.Argon2idParams) { p.MemoryKiB, p.Parallelism = 16, 2 }),
		"default": {},
	} {
		assert.NotPanics(t, func() { password.NewArgon2idHasher(p) }, name)
	}
}

// Audit CORE-06 (probe TestZZAuditBCrypt): the cost of a stored bcrypt hash
// was honored up to 31 (cost 31 ≈ 34 h of CPU per attempt). The stored cost
// is read before any hashing and bounded by an inclusive limit (default 14,
// raised to the hasher's own cost).
func TestBCryptVerifyRefusesStoredCostAboveTheLimit(t *testing.T) {
	t.Parallel()

	h := password.NewBCryptHasher(4, password.WithBCryptMaxCost(5))
	assert.Equal(t, 5, h.MaxCost())

	atLimit, err := bcrypt.GenerateFromPassword([]byte("pw"), 5)
	require.NoError(t, err)

	ok, err := h.Verify(context.Background(), string(atLimit), "pw")
	require.NoError(t, err)
	assert.True(t, ok, "the limit is inclusive")

	above, err := bcrypt.GenerateFromPassword([]byte("pw"), 6)
	require.NoError(t, err)

	ok, err = h.Verify(context.Background(), string(above), "pw")
	require.ErrorIs(t, err, password.ErrCostLimitExceeded)
	assert.False(t, ok)
	assert.True(t, h.NeedsRehash(string(above)))

	cost31 := strings.Replace(string(above), "$06$", "$31$", 1)

	ok, err = h.Verify(context.Background(), cost31, "pw")
	require.ErrorIs(t, err, password.ErrCostLimitExceeded, "refused before hashing: cost 31 would run for hours")
	assert.False(t, ok)
}

func TestBCryptDefaultMaxCostIsInclusive(t *testing.T) {
	t.Parallel()

	h := password.NewBCryptHasher(4)
	assert.Equal(t, password.DefaultBCryptMaxCost, h.MaxCost())
	assert.Equal(t, 14, password.DefaultBCryptMaxCost)

	cost4, err := bcrypt.GenerateFromPassword([]byte("pw"), 4)
	require.NoError(t, err)

	// NeedsRehash parses the cost without hashing: false = accepted and at
	// least as strong as the configuration, true = refused.
	assert.False(t, h.NeedsRehash(strings.Replace(string(cost4), "$04$", "$14$", 1)))
	assert.True(t, h.NeedsRehash(strings.Replace(string(cost4), "$04$", "$15$", 1)))

	// The limit is raised to the hasher's own cost.
	assert.Equal(t, 16, password.NewBCryptHasher(16).MaxCost())
	assert.Equal(t, 12, password.NewBCryptHasher(12, password.WithBCryptMaxCost(5)).MaxCost())
}

func TestBCryptConstructorBounds(t *testing.T) {
	t.Parallel()

	assert.Equal(t, 10, password.NewBCryptHasher(0).Cost(), "0 selects bcrypt.DefaultCost, which is 10")
	assert.Equal(t, 4, password.NewBCryptHasher(4).Cost())
	assert.Equal(t, 31, password.NewBCryptHasher(31).Cost())

	for _, cost := range []int{-1, 1, 3, 32, 50} {
		assert.Panics(t, func() { password.NewBCryptHasher(cost) }, "cost %d", cost)
	}

	for _, cost := range []int{-1, 0, 3, 32} {
		assert.Panics(t, func() { password.WithBCryptMaxCost(cost) }, "max cost %d", cost)
	}
}

// A malformed bcrypt hash is reported as ErrMalformedHash.
func TestBCryptVerifyReportsMalformedHashes(t *testing.T) {
	t.Parallel()

	h := password.NewBCryptHasher(4)

	for _, hash := range []string{"$2a$", "$2a$04$tooshort", "$2a$xx$" + strings.Repeat("a", 53)} {
		ok, err := h.Verify(context.Background(), hash, "pw")
		require.ErrorIs(t, err, password.ErrMalformedHash, hash)
		assert.False(t, ok)
		assert.True(t, h.NeedsRehash(hash))
	}
}

// The encoded hash is bounded before it is split and decoded: a hostile
// multi-megabyte "hash" costs nothing. (Not parallel: it reads the
// process-wide allocation counter.)
func TestArgon2idBoundsTheEncodedHashBeforeParsing(t *testing.T) {
	h := tinyLimitsHasher()
	huge := "$argon2id$v=19$" + strings.Repeat("$", 4<<20)

	var before, after runtime.MemStats

	runtime.ReadMemStats(&before)

	_, err := h.Verify(context.Background(), huge, "pw")

	runtime.ReadMemStats(&after)

	require.ErrorIs(t, err, password.ErrMalformedHash)
	assert.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(1<<20), "the hash must be refused before being split")
	assert.True(t, h.NeedsRehash(huge))
}
