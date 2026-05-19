// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package password_test

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/hyperscale-stack/security/password"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fast2idParams is a deliberately cheap parameter set used in unit tests so
// the whole suite stays under a few hundred ms while still exercising every
// code path.
func fast2idParams() password.Argon2idParams {
	return password.Argon2idParams{
		MemoryKiB:   8 * 1024, // 8 MiB
		Time:        1,
		Parallelism: 1,
		KeyLen:      32,
		SaltLen:     16,
	}
}

func TestArgon2idRoundTrip(t *testing.T) {
	t.Parallel()

	h := password.NewArgon2idHasher(fast2idParams())

	encoded, err := h.Hash(context.Background(), "p4ssw0rd")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(encoded, "$argon2id$"), "got %q", encoded)

	ok, err := h.Verify(context.Background(), encoded, "p4ssw0rd")
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestArgon2idMismatchReturnsFalseNilError(t *testing.T) {
	t.Parallel()

	h := password.NewArgon2idHasher(fast2idParams())
	encoded, _ := h.Hash(context.Background(), "right")

	ok, err := h.Verify(context.Background(), encoded, "wrong")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestArgon2idVerifyRejectsWrongAlgorithm(t *testing.T) {
	t.Parallel()

	h := password.NewArgon2idHasher(fast2idParams())

	_, err := h.Verify(context.Background(), "$2a$04$abc", "x")
	assert.ErrorIs(t, err, password.ErrUnsupportedAlgorithm)
}

func TestArgon2idVerifyRejectsMalformedHash(t *testing.T) {
	t.Parallel()

	h := password.NewArgon2idHasher(fast2idParams())

	cases := []string{
		"",
		"$argon2id$v=19",                       // too few fields
		"$argon2id$v=99$m=8,t=1,p=1$aaa$bbb",   // wrong version
		"$argon2id$v=19$m=x,t=1,p=1$aaa$bbb",   // bad memory
		"$argon2id$v=19$m=8,t=1,p=1$!!$bbb",    // bad base64 salt
		"$argon2id$v=19$m=8,t=1,p=1$aGVsbG8$!!",// bad base64 key
	}
	for _, c := range cases {
		_, err := h.Verify(context.Background(), c, "x")
		assert.ErrorIsf(t, err, password.ErrMalformedHash, "input %q", c)
	}
}

func TestArgon2idNeedsRehashOnWeakerParameters(t *testing.T) {
	t.Parallel()

	lo := password.NewArgon2idHasher(password.Argon2idParams{
		MemoryKiB: 8 * 1024, Time: 1, Parallelism: 1, KeyLen: 32, SaltLen: 16,
	})
	hi := password.NewArgon2idHasher(password.Argon2idParams{
		MemoryKiB: 16 * 1024, Time: 2, Parallelism: 1, KeyLen: 32, SaltLen: 16,
	})

	encoded, _ := lo.Hash(context.Background(), "x")
	assert.False(t, lo.NeedsRehash(encoded))
	assert.True(t, hi.NeedsRehash(encoded), "stored params weaker than configured")
	assert.True(t, lo.NeedsRehash("$2a$04$xxx"), "cross-algorithm triggers rehash")
}

func TestArgon2idHashIsRandomized(t *testing.T) {
	t.Parallel()

	h := password.NewArgon2idHasher(fast2idParams())
	a, _ := h.Hash(context.Background(), "same")
	b, _ := h.Hash(context.Background(), "same")
	assert.NotEqual(t, a, b, "fresh salt per call must produce different hashes")
}

func TestDefaultArgon2idParamsMatchOWASP(t *testing.T) {
	t.Parallel()

	p := password.DefaultArgon2idParams()
	assert.Equal(t, uint32(19*1024), p.MemoryKiB, "OWASP 2024 baseline = 19 MiB")
	assert.Equal(t, uint32(2), p.Time)
	assert.Equal(t, uint8(1), p.Parallelism)
	assert.Equal(t, uint32(32), p.KeyLen)
	assert.Equal(t, uint32(16), p.SaltLen)
}

func TestArgon2idZeroParamsAreReplacedWithDefaults(t *testing.T) {
	t.Parallel()

	h := password.NewArgon2idHasher(password.Argon2idParams{})
	def := password.DefaultArgon2idParams()
	assert.Equal(t, def, h.Params(), "all-zero input must reuse the OWASP defaults")
}

func TestArgon2idIsRaceSafe(t *testing.T) {
	t.Parallel()

	h := password.NewArgon2idHasher(fast2idParams())
	encoded, _ := h.Hash(context.Background(), "x")

	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)

		go func() {
			defer wg.Done()
			ok, err := h.Verify(context.Background(), encoded, "x")
			assert.NoError(t, err)
			assert.True(t, ok)
		}()
	}

	wg.Wait()
}

func TestArgon2idContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := password.NewArgon2idHasher(fast2idParams()).Hash(ctx, "x")
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}
