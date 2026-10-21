// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package password_test

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/hyperscale-stack/security/password"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nonZeroTrailingBits re-encodes b64, an unpadded base64 value whose
// length leaves bits unused in its last character, with those bits set:
// the same bytes in a non-canonical encoding (C2SP phc-strings: "a sequence
// of characters of the right length may still be an invalid encoding if it
// defines some non-zero trailing bits").
func nonZeroTrailingBits(t *testing.T, b64 string) string {
	t.Helper()

	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

	last := strings.IndexByte(alphabet, b64[len(b64)-1])
	require.GreaterOrEqual(t, last, 0)

	out := b64[:len(b64)-1] + string(alphabet[last|1])
	require.NotEqual(t, b64, out, "the length leaves trailing bits")

	lax, err := base64.RawStdEncoding.DecodeString(out)
	require.NoError(t, err)

	canonical, err := base64.RawStdEncoding.DecodeString(b64)
	require.NoError(t, err)
	require.Equal(t, canonical, lax, "the same bytes")

	return out
}

// Audit I-30: the argon2id parser accepted non-canonical encodings of a
// hash — leading zeros, CR and LF inside the base64 values (which
// encoding/base64 skips, even in strict mode), non-zero trailing bits, and
// the parameters in any order. C2SP phc-strings: decimal values have "no
// leading zero", base64 values allow no extra characters, "producers MUST
// set the trailing bits to 0, while consumers MAY ignore them, or MAY
// reject such invalid encodings", parameters appear in the order the
// function defines. One stored hash has one encoding.
func TestArgon2idVerifyRefusesNonCanonicalEncodings(t *testing.T) {
	t.Parallel()

	h := tinyLimitsHasher()
	good := realPHC("pw", 64, 1, 1, 16, 32)
	parts := strings.Split(good, "$")
	params, salt, tag := parts[3], parts[4], parts[5]
	with := func(p, s, g string) string { return "$argon2id$v=19$" + p + "$" + s + "$" + g }

	ok, err := h.Verify(context.Background(), good, "pw")
	require.NoError(t, err)
	require.True(t, ok, "the canonical encoding verifies")
	require.Equal(t, "m=64,t=1,p=1", params)

	cases := map[string]string{
		"leading zero in m":        with("m=064,t=1,p=1", salt, tag),
		"leading zeros everywhere": with("m=0064,t=01,p=001", salt, tag),
		"t zero-padded":            with("m=64,t=01,p=1", salt, tag),
		"p zero-padded":            with("m=64,t=1,p=01", salt, tag),
		"parameters reordered":     with("t=1,p=1,m=64", salt, tag),
		"p before t":               with("m=64,p=1,t=1", salt, tag),
		"LF in the salt":           with(params, salt[:4]+"\n"+salt[4:], tag),
		"CR in the tag":            with(params, salt, tag[:4]+"\r"+tag[4:]),
		"CRLF at the tag's end":    with(params, salt, tag+"\r\n"),
		"space in the salt":        with(params, salt[:4]+" "+salt[4:], tag),
		"URL alphabet":             with(params, strings.NewReplacer("+", "-", "/", "_").Replace(salt)+"-", tag),
		"salt trailing bits":       with(params, nonZeroTrailingBits(t, salt), tag),
		"tag trailing bits":        with(params, salt, nonZeroTrailingBits(t, tag)),
	}

	for name, hash := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ok, err := verifyNoPanic(t, h, hash, "pw")
			require.ErrorIs(t, err, password.ErrMalformedHash)
			assert.False(t, ok)
			assert.True(t, h.NeedsRehash(hash))
		})
	}
}

// Audit I-30: bcrypt accepted "$2x$" — the prefix crypt_blowfish gives the
// hashes of its sign-extension bug, which x/crypto would verify as "$2a$"
// — and "$2$", the pre-2a format. Only "$2a$", "$2b$" and "$2y$" are
// bcrypt hashes this hasher verifies.
func TestBCryptVerifiesOnlyTheCurrentVersions(t *testing.T) {
	t.Parallel()

	h := password.NewBCryptHasher(4)

	hash, err := h.Hash(context.Background(), "pw")
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(hash, "$2a$"))

	body := hash[len("$2a$"):]

	for _, version := range []string{"$2a$", "$2b$", "$2y$"} {
		ok, err := h.Verify(context.Background(), version+body, "pw")
		require.NoError(t, err, version)
		assert.True(t, ok, version)
	}

	for _, prefix := range []string{"$2x$", "$2$", "$2c$", "$2A$", "$2ab$", "$3a$"} {
		ok, err := h.Verify(context.Background(), prefix+body, "pw")
		require.ErrorIs(t, err, password.ErrUnsupportedAlgorithm, prefix)
		assert.False(t, ok, prefix)
		assert.True(t, h.NeedsRehash(prefix+body), prefix)
	}
}
