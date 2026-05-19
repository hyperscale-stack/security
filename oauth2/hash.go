// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// HashToken returns the canonical one-way hash used by the storage layer to
// look tokens up without ever persisting the raw value. The pepper
// parameter SHOULD be a server-wide secret (32 random bytes or more) so an
// attacker who steals the storage table cannot validate guessed tokens
// offline by re-hashing them.
//
// Callers SHOULD wrap this in a small helper that captures the pepper once
// at server construction time rather than passing it around.
func HashToken(pepper []byte, token string) string {
	mac := hmac.New(sha256.New, pepper)
	mac.Write([]byte(token))

	return hex.EncodeToString(mac.Sum(nil))
}
