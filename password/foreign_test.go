// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package password_test

import (
	"context"
	"testing"

	"github.com/hyperscale-stack/security/password"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Hashes of "correct horse" produced by other implementations — PHP 8.5
// (password_hash with the libargon2 reference encoder, crypt with
// crypt_blowfish) and libsodium (sodium_crypto_pwhash_str) —, so that a
// future tightening of the parsers cannot silently lock their users out
// (review nit 6). Every one is canonical and verifies; crypt_blowfish's
// $2x$ marker of its sign-extension bug is refused.
func TestForeignHashesStillVerify(t *testing.T) {
	t.Parallel()

	argon2id := map[string]string{
		"PHP password_hash":          "$argon2id$v=19$m=1024,t=2,p=1$MWRab0JNd2lYNmdwVk1YeA$stpoVFkbx54eAPRYrdDX2+XKBe+CoIU5Y0C6/jH1xh8",
		"PHP password_hash, 2 lanes": "$argon2id$v=19$m=4096,t=3,p=2$eHBQei9FYzAvRHBVZ0tKRA$0orWCiRmpa9bWSuDyVRiYbDS+ob4/3vPhnWGou0KSZg",
		"libsodium pwhash_str":       "$argon2id$v=19$m=1024,t=3,p=1$Sg/taQVUZeBr/67gkGhvWw$xma9s/IrJTzCqa7NEgGqAyuLeF7LQjSiatDTEUmRQYk",
	}
	bcrypt := map[string]string{
		"PHP password_hash $2y$": "$2y$04$zr30cgcVjuQjV6kB1FUanOKLkk5cANWA0DcEtChavXRBJi1D2XCJG",
		"crypt_blowfish $2a$":    "$2a$04$abcdefghijklmnopqrstuujydOTSfIH/d5oUHpsygqV5X9xJLQc6e",
		"crypt_blowfish $2b$":    "$2b$04$abcdefghijklmnopqrstuujydOTSfIH/d5oUHpsygqV5X9xJLQc6e",
	}

	verify := func(t *testing.T, h password.Hasher, hashes map[string]string) {
		t.Helper()

		for name, hash := range hashes {
			ok, err := h.Verify(context.Background(), hash, "correct horse")
			require.NoError(t, err, name)
			assert.True(t, ok, name)

			ok, err = h.Verify(context.Background(), hash, "wrong horse")
			require.NoError(t, err, name)
			assert.False(t, ok, name)
		}
	}

	verify(t, password.NewArgon2idHasher(password.Argon2idParams{}), argon2id)
	verify(t, password.NewBCryptHasher(4), bcrypt)

	ok, err := password.NewBCryptHasher(4).Verify(context.Background(),
		"$2x$04$abcdefghijklmnopqrstuujydOTSfIH/d5oUHpsygqV5X9xJLQc6e", "correct horse")
	require.ErrorIs(t, err, password.ErrUnsupportedAlgorithm)
	assert.False(t, ok)
}
