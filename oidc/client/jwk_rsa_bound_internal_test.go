// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient

import (
	"encoding/base64"
	"math/big"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// keySetOfBits is a JWK Set holding one RS256 public key whose modulus has
// exactly bits bits.
func keySetOfBits(bits uint) []byte {
	n := new(big.Int).Lsh(big.NewInt(1), bits-1)
	n.Or(n, big.NewInt(1))

	return []byte(`{"keys":[{"kty":"RSA","alg":"RS256","use":"sig","kid":"k","n":"` +
		base64.RawURLEncoding.EncodeToString(n.Bytes()) + `","e":"AQAB"}]}`)
}

// rsaBounds are the RSA moduli a provider's JWK Set may use: 2048 bits
// (RFC 7518 §3.3) to 4096 bits (go-jose ≥ v4.1.6's default cap, kept as
// the package's own bound).
var rsaBounds = map[uint]bool{2047: false, 2048: true, 4096: true, 4097: false, 8192: false}

// TestParseKeySetRSABounds pins the 2048–4096-bit range of RSA keys: a key
// outside it is ignored (RFC 7517 §5), the set stays usable.
func TestParseKeySetRSABounds(t *testing.T) {
	t.Parallel()

	for bits, usable := range rsaBounds {
		keys, err := parseKeySet(keySetOfBits(bits))
		require.NoError(t, err)
		assert.Equal(t, usable, len(keys) == 1, "%d bits", bits)
	}
}

// TestParseKeySetRSABoundIgnoresGoJoseGlobal pins that the 4096-bit bound
// is the package's own: it holds when the application raises go-jose's
// process-wide jose.MaxRSAModulusBits. Not parallel: it mutates that
// global, and parallel tests only start once the sequential ones are done.
func TestParseKeySetRSABoundIgnoresGoJoseGlobal(t *testing.T) {
	saved := jose.MaxRSAModulusBits
	jose.MaxRSAModulusBits = 8192

	t.Cleanup(func() { jose.MaxRSAModulusBits = saved })

	for bits, usable := range rsaBounds {
		keys, err := parseKeySet(keySetOfBits(bits))
		require.NoError(t, err)
		assert.Equal(t, usable, len(keys) == 1, "%d bits", bits)
	}
}
