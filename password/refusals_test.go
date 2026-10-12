// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package password_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hyperscale-stack/security/password"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// Audit CORE-I7 (probe TestZZAuditBCrypt): Hash refused a password longer
// than 72 bytes while Verify silently compared its first 72 bytes —
// Verify(pw72+suffix) succeeded. NIST SP 800-63B-4 §3.1.1.2: verifiers SHALL
// verify the entire submitted password and not truncate it.
func TestBCryptRefusesPasswordsLongerThan72Bytes(t *testing.T) {
	t.Parallel()

	h := password.NewBCryptHasher(4)
	pw72 := strings.Repeat("A", 72)

	hash, err := h.Hash(context.Background(), pw72)
	require.NoError(t, err, "72 bytes is the longest password bcrypt processes whole")

	ok, err := h.Verify(context.Background(), hash, pw72)
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = h.Verify(context.Background(), hash, pw72+"-anything-appended")
	require.ErrorIs(t, err, password.ErrPasswordTooLong)
	assert.False(t, ok)

	_, err = h.Hash(context.Background(), pw72+"x")
	require.ErrorIs(t, err, password.ErrPasswordTooLong)

	// 18 four-byte UTF-8 characters fill the 72 bytes.
	emoji := strings.Repeat("😀", 19)
	_, err = h.Verify(context.Background(), hash, emoji)
	require.ErrorIs(t, err, password.ErrPasswordTooLong)
}

// Audit CORE-I7: empty passwords hashed and verified. RFC 8265 §4.1: "A
// password MUST NOT be zero bytes in length".
func TestHashRefusesAnEmptyPassword(t *testing.T) {
	t.Parallel()

	for name, h := range map[string]password.Hasher{
		"bcrypt":   password.NewBCryptHasher(4),
		"argon2id": password.NewArgon2idHasher(fast2idParams()),
	} {
		_, err := h.Hash(context.Background(), "")
		require.ErrorIs(t, err, password.ErrEmptyPassword, name)
	}
}

// A stored hash of the empty password — made by another system — never
// authenticates an empty password.
func TestVerifyNeverAcceptsAnEmptyPassword(t *testing.T) {
	t.Parallel()

	bcryptEmpty, err := bcrypt.GenerateFromPassword(nil, 4)
	require.NoError(t, err)

	cases := map[string]struct {
		h    password.Hasher
		hash string
	}{
		"bcrypt":   {password.NewBCryptHasher(4), string(bcryptEmpty)},
		"argon2id": {tinyLimitsHasher(), realPHC("", 8, 1, 1, 16, 32)},
	}

	for name, c := range cases {
		ok, err := c.h.Verify(context.Background(), c.hash, "")
		require.NoError(t, err, name)
		assert.False(t, ok, name)
	}
}

// Positive observation of the audit, pinned: NUL bytes are data, not
// terminators.
func TestNULIsData(t *testing.T) {
	t.Parallel()

	for name, h := range map[string]password.Hasher{
		"bcrypt":   password.NewBCryptHasher(4),
		"argon2id": password.NewArgon2idHasher(fast2idParams()),
	} {
		hash, err := h.Hash(context.Background(), "a\x00b")
		require.NoError(t, err, name)

		ok, err := h.Verify(context.Background(), hash, "a")
		require.NoError(t, err, name)
		assert.False(t, ok, name)

		ok, err = h.Verify(context.Background(), hash, "a\x00b")
		require.NoError(t, err, name)
		assert.True(t, ok, name)
	}
}

// The sentinels are distinct: application code branches on them.
func TestSentinelsAreDistinct(t *testing.T) {
	t.Parallel()

	all := []error{
		password.ErrMismatch, password.ErrUnsupportedAlgorithm, password.ErrMalformedHash,
		password.ErrCostLimitExceeded, password.ErrPasswordTooLong, password.ErrEmptyPassword,
	}

	for i, a := range all {
		for j, b := range all {
			assert.Equal(t, i == j, errors.Is(a, b), "%v vs %v", a, b)
		}
	}
}

// FuzzArgon2idDecode: no stored hash makes Verify or NeedsRehash panic, and
// Verify only ever reports the documented errors. The limits keep every
// accepted hash cheap.
func FuzzArgon2idDecode(f *testing.F) {
	h := tinyLimitsHasher()

	f.Add(realPHC("pw", 8, 1, 1, 16, 32))
	f.Add(phc("m=64,t=0,p=1", bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 32)))
	f.Add("$argon2id$v=19$m=4294967295,t=4294967295,p=255$MDEyMzQ1Njc4OWFiY2RlZg$AAAAAAAAAAAAAAAAAAAAAA")
	f.Add("$argon2id$v=19$m=64$$")
	f.Add("$2a$04$abc")
	f.Add("")

	f.Fuzz(func(t *testing.T, hash string) {
		_ = h.NeedsRehash(hash)

		_, err := h.Verify(context.Background(), hash, "pw")
		if err != nil && !errors.Is(err, password.ErrMalformedHash) &&
			!errors.Is(err, password.ErrUnsupportedAlgorithm) && !errors.Is(err, password.ErrCostLimitExceeded) {
			t.Fatalf("Verify(%q) returned an undocumented error: %v", hash, err)
		}
	})
}

// Verify honors a canceled context before any work, for both hashers.
func TestVerifyHonorsACanceledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	bcryptHash, err := bcrypt.GenerateFromPassword([]byte("pw"), 4)
	require.NoError(t, err)

	for name, c := range map[string]struct {
		h    password.Hasher
		hash string
	}{
		"bcrypt":   {password.NewBCryptHasher(4), string(bcryptHash)},
		"argon2id": {tinyLimitsHasher(), realPHC("pw", 8, 1, 1, 16, 32)},
	} {
		ok, err := c.h.Verify(ctx, c.hash, "pw")
		require.ErrorIs(t, err, context.Canceled, name)
		assert.False(t, ok, name)
	}
}

// A bcrypt hash whose cost parses but whose salt is not bcrypt base64 is
// malformed, not a mismatch.
func TestBCryptVerifyReportsACorruptedSalt(t *testing.T) {
	t.Parallel()

	good, err := bcrypt.GenerateFromPassword([]byte("pw"), 4)
	require.NoError(t, err)

	corrupted := string(good[:7]) + strings.Repeat("!", len(good)-7)

	ok, err := password.NewBCryptHasher(4).Verify(context.Background(), corrupted, "pw")
	require.ErrorIs(t, err, password.ErrMalformedHash)
	assert.False(t, ok)
}
