// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session_test

import (
	"strings"
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

	encoded, err := codec.SealForTest(sampleSession(), "session", "")
	require.NoError(t, err)
	assert.NotEmpty(t, encoded)

	got, err := codec.OpenForTest(encoded, "session", "")
	require.NoError(t, err)
	assert.Equal(t, "sid-1", got.ID)
	assert.Equal(t, "alice", got.GetString("sub"))
	assert.Equal(t, "csrf-token-value", got.CSRFToken)
	assert.True(t, got.CreatedAt.Equal(sampleSession().CreatedAt))
	assert.True(t, got.ExpiresAt.Equal(sampleSession().ExpiresAt))
}

func TestCodecSealIsRandomised(t *testing.T) {
	t.Parallel()

	codec, _ := session.NewCodec(testKey)

	a, _ := codec.SealForTest(sampleSession(), "session", "")
	b, _ := codec.SealForTest(sampleSession(), "session", "")
	assert.NotEqual(t, a, b, "a fresh GCM nonce per call must change the ciphertext")
}

func TestCodecRejectsTamperedValue(t *testing.T) {
	t.Parallel()

	codec, _ := session.NewCodec(testKey)
	encoded, _ := codec.SealForTest(sampleSession(), "session", "")

	// Flip the last byte — the GCM tag check must fail.
	tampered := encoded[:len(encoded)-1] + flipChar(encoded[len(encoded)-1])

	_, err := codec.OpenForTest(tampered, "session", "")
	assert.ErrorIs(t, err, session.ErrDecode)
}

func TestCodecRejectsGarbage(t *testing.T) {
	t.Parallel()

	codec, _ := session.NewCodec(testKey)

	for _, bad := range []string{"", "!!!not base64!!!", "c2hvcnQ", "Ag", strings.Repeat("A", 4097)} {
		_, err := codec.OpenForTest(bad, "session", "")
		assert.ErrorIs(t, err, session.ErrDecode, "input %.20q", bad)
	}
}

func flipChar(b byte) string {
	if b == 'A' {
		return "B"
	}

	return "A"
}
