// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	jose "github.com/go-jose/go-jose/v4"
	josejson "github.com/go-jose/go-jose/v4/json"
)

// unsupportedHeaders are the JOSE header parameters of the JWS extensions
// this package does not implement, refused whatever their value: crit
// (RFC 7515 §4.1.11 — a JWS whose crit lists an extension the recipient
// does not support is invalid, and crit is never an empty list) and b64
// (RFC 7797 §6 — it always comes with crit; §7 — a JWT MUST NOT use b64
// with a false value).
var unsupportedHeaders = []string{"crit", "b64"}

// parseCompact parses token as a JWS Compact Serialization (RFC 7515 §7.1)
// signed with one of allowed, after the checks of checkCompact. A failure
// wraps [ErrMalformedToken], or [ErrAlgorithmNotAllowed] for an algorithm
// outside allowed — never the token or an unbounded part of it.
func parseCompact(token string, allowed []Algorithm, maxSize int) (*jose.JSONWebSignature, jose.Header, error) {
	if err := checkCompact(token, maxSize); err != nil {
		return nil, jose.Header{}, err
	}

	parsed, err := jose.ParseSignedCompact(token, joseAllowed(allowed))
	if err != nil {
		var algErr *jose.ErrUnexpectedSignatureAlgorithm
		if errors.As(err, &algErr) {
			return nil, jose.Header{}, &errAlgorithmDisallowed{alg: clip(string(algErr.Got))}
		}

		// go-jose quotes raw header values in its messages: clip them.
		return nil, jose.Header{}, fmt.Errorf("%w: %w", ErrMalformedToken, clippedError{err: err})
	}

	// Defense in depth: the compact serialization carries one signature.
	if len(parsed.Signatures) != 1 {
		return nil, jose.Header{}, fmt.Errorf("%w: expected exactly one signature", ErrMalformedToken)
	}

	return parsed, parsed.Signatures[0].Header, nil
}

// checkCompact refuses, before any JOSE parsing, a token longer than
// maxSize bytes (go-jose decodes the header into maps, about 100 times
// its size, before checking the algorithm), a token that is not three
// segments of canonical unpadded base64url — no whitespace, padding or
// other characters (RFC 7515 §2, RFC 7519 §7.2 steps 3 and 9), no
// non-zero pad bits (RFC 4648 §3.5), so a token has one encoding — with a
// non-empty header and payload, and a header that is not a strict JSON
// object (see checkHeader).
func checkCompact(token string, maxSize int) error {
	if len(token) > maxSize {
		return fmt.Errorf("%w: token larger than %d bytes", ErrMalformedToken, maxSize)
	}

	head, rest, ok := strings.Cut(token, ".")
	payload, signature, ok2 := strings.Cut(rest, ".")

	if !ok || !ok2 || strings.Contains(signature, ".") {
		return fmt.Errorf("%w: not a JWS compact serialization", ErrMalformedToken)
	}

	if head == "" || payload == "" {
		return fmt.Errorf("%w: empty header or payload", ErrMalformedToken)
	}

	for _, segment := range []string{head, payload, signature} {
		if !canonicalBase64URL(segment) {
			return fmt.Errorf("%w: not canonical base64url", ErrMalformedToken)
		}
	}

	raw, err := base64.RawURLEncoding.DecodeString(head)
	if err != nil {
		return fmt.Errorf("%w: header: %w", ErrMalformedToken, err)
	}

	return checkHeader(raw)
}

// checkHeader refuses a JOSE header that is not a strict JSON object —
// valid UTF-8 without unpaired surrogate escapes, unique parameter names
// even under case folding (RFC 7515 §4, RFC 7519 §7.2 step 4; see
// validateJSON) — or that uses an extension this package does not
// implement (unsupportedHeaders), whatever its value, null included: go-jose
// treats a null crit or b64 as absent.
func checkHeader(raw []byte) error {
	var members map[string]josejson.RawMessage
	if err := decodeStrict(raw, &members); err != nil {
		return fmt.Errorf("%w: header: %w", ErrMalformedToken, err)
	}

	for _, name := range unsupportedHeaders {
		if _, ok := members[name]; ok {
			return fmt.Errorf("%w: unsupported %q header parameter", ErrMalformedToken, name)
		}
	}

	return nil
}

// canonicalBase64URL reports whether s is the canonical unpadded base64url
// encoding of some octets (RFC 4648 §5, §3.5): only the URL-safe alphabet,
// a length that is not 1 modulo 4, and zero pad bits in the last character.
func canonicalBase64URL(s string) bool {
	for i := range len(s) {
		if base64URLValue(s[i]) < 0 {
			return false
		}
	}

	switch len(s) % 4 {
	case 1:
		return false
	case 2: // 12 bits, the last 4 unused
		return base64URLValue(s[len(s)-1])&0x0f == 0
	case 3: // 18 bits, the last 2 unused
		return base64URLValue(s[len(s)-1])&0x03 == 0
	default:
		return true
	}
}

// base64URLValue returns the 6-bit value of c in the base64url alphabet,
// -1 when c is not in it.
func base64URLValue(c byte) int {
	switch {
	case c >= 'A' && c <= 'Z':
		return int(c - 'A')
	case c >= 'a' && c <= 'z':
		return int(c-'a') + 26
	case c >= '0' && c <= '9':
		return int(c-'0') + 52
	case c == '-':
		return 62
	case c == '_':
		return 63
	default:
		return -1
	}
}
