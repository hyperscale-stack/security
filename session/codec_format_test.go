// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"testing"

	"github.com/hyperscale-stack/security/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCodecRedactsItsKeys: a Codec printed with any fmt verb — alone or in
// a configuration — or logged through slog never reveals its keys. Without
// its own Format, fmt prints the AES-256 key schedule behind its ciphers,
// which starts with the encryption key, for the verbs a pointer does not
// take (%s, %q, %t…). (%p of a value is left out: fmt prints the fields of
// a value for that invalid verb before any method, which no type can
// redact.)
func TestCodecRedactsItsKeys(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0x5a}, 32)
	derived := sha256.Sum256(key) // the AES-256 key of the active key

	codec, err := session.NewCodec(key, []byte("previous-key"))
	require.NoError(t, err)

	// The first word of the key schedule, as fmt prints it on either byte order.
	words := []string{
		strconv.FormatUint(uint64(binary.BigEndian.Uint32(derived[:4])), 10),
		strconv.FormatUint(uint64(binary.LittleEndian.Uint32(derived[:4])), 10),
	}

	const want = "session.Codec{Keys: 2}"

	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%t", "%o", "%b", "%e", "%U", "%c"} {
		printed := fmt.Sprintf(verb, codec)
		nested := fmt.Sprintf(verb, struct{ Codec *session.Codec }{codec})

		for _, w := range words {
			assert.NotContains(t, printed, w, "printed with %s", verb)
			assert.NotContains(t, nested, w, "nested, printed with %s", verb)
		}

		assert.Equal(t, want, printed, "printed with %s", verb)
		assert.Contains(t, nested, want+"}", "nested, printed with %s", verb)
	}

	var text, js strings.Builder

	slog.New(slog.NewTextHandler(&text, nil)).Info("codec", "codec", codec)
	slog.New(slog.NewJSONHandler(&js, nil)).Info("codec", "codec", codec)

	assert.Contains(t, text.String(), want)

	for _, out := range []string{text.String(), js.String()} {
		for _, w := range words {
			assert.NotContains(t, out, w)
		}
	}
}
