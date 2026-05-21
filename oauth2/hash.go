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
// look tokens up without ever persisting the raw value.
//
// pepper is an optional HMAC key. The shipped token machinery — the
// generators in oauth2/token and every server lookup path (grants,
// /introspect, /revoke) — calls HashToken with a nil pepper: OAuth2 tokens
// and codes carry ≥ 128 bits of entropy, so a bare SHA-256 is already
// preimage- and brute-force-resistant. Pass a non-nil pepper only if you
// hash some lower-entropy value AND every party that looks it up uses the
// exact same key.
func HashToken(pepper []byte, token string) string {
	mac := hmac.New(sha256.New, pepper)
	mac.Write([]byte(token))

	return hex.EncodeToString(mac.Sum(nil))
}
