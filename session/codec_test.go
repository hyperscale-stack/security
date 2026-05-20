// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session_test

import (
	"testing"
	"time"

	"github.com/hyperscale-stack/security/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sampleSession() *session.Session {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)

	return &session.Session{
		ID:           "sid-1",
		Values:       map[string]any{"sub": "alice", "tenant": "acme"},
		CSRFToken:    "csrf-token-value",
		CreatedAt:    now,
		LastAccessed: now,
		ExpiresAt:    now.Add(time.Hour),
	}
}

func TestCodecRoundTrip(t *testing.T) {
	t.Parallel()

	codec, err := session.NewCodec(testKey)
	require.NoError(t, err)

	encoded, err := codec.Encode(sampleSession())
	require.NoError(t, err)
	assert.NotEmpty(t, encoded)

	got, err := codec.Decode(encoded)
	require.NoError(t, err)
	assert.Equal(t, "sid-1", got.ID)
	assert.Equal(t, "alice", got.GetString("sub"))
	assert.Equal(t, "csrf-token-value", got.CSRFToken)
}

func TestCodecEncodeIsRandomised(t *testing.T) {
	t.Parallel()

	codec, _ := session.NewCodec(testKey)

	a, _ := codec.Encode(sampleSession())
	b, _ := codec.Encode(sampleSession())
	assert.NotEqual(t, a, b, "a fresh GCM nonce per call must change the ciphertext")
}

func TestCodecRejectsTamperedValue(t *testing.T) {
	t.Parallel()

	codec, _ := session.NewCodec(testKey)
	encoded, _ := codec.Encode(sampleSession())

	// Flip the last byte — the GCM tag check must fail.
	tampered := encoded[:len(encoded)-1] + flipChar(encoded[len(encoded)-1])

	_, err := codec.Decode(tampered)
	assert.ErrorIs(t, err, session.ErrDecode)
}

func TestCodecRejectsGarbage(t *testing.T) {
	t.Parallel()

	codec, _ := session.NewCodec(testKey)

	for _, bad := range []string{"", "!!!not base64!!!", "c2hvcnQ"} {
		_, err := codec.Decode(bad)
		assert.ErrorIs(t, err, session.ErrDecode, "input %q", bad)
	}
}

func TestCodecKeyRotation(t *testing.T) {
	t.Parallel()

	oldKey := []byte("old-key-old-key-old-key-old-key!")
	newKey := []byte("new-key-new-key-new-key-new-key!")

	// A cookie sealed by the old codec...
	oldCodec, _ := session.NewCodec(oldKey)
	sealed, err := oldCodec.Encode(sampleSession())
	require.NoError(t, err)

	// ...still decodes after rotation when the old key is kept as a
	// decrypt-only key (new key first = active for encryption).
	rotated, err := session.NewCodec(newKey, oldKey)
	require.NoError(t, err)

	got, err := rotated.Decode(sealed)
	require.NoError(t, err)
	assert.Equal(t, "sid-1", got.ID)

	// A codec that dropped the old key can no longer read the cookie.
	newOnly, _ := session.NewCodec(newKey)
	_, err = newOnly.Decode(sealed)
	assert.ErrorIs(t, err, session.ErrDecode)
}

func TestNewCodecRequiresAKey(t *testing.T) {
	t.Parallel()

	_, err := session.NewCodec()
	assert.ErrorIs(t, err, session.ErrInvalidKeys)
}

func flipChar(b byte) string {
	if b == 'A' {
		return "B"
	}

	return "A"
}
