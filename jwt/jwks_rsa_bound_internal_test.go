// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec

import (
	"encoding/base64"
	"math/big"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
)

// rsaJWKOfBits is an RS256 public JWK whose modulus has exactly bits bits.
func rsaJWKOfBits(bits uint) []byte {
	n := new(big.Int).Lsh(big.NewInt(1), bits-1)
	n.Or(n, big.NewInt(1))

	return []byte(`{"kty":"RSA","alg":"RS256","use":"sig","kid":"k","n":"` + base64.RawURLEncoding.EncodeToString(n.Bytes()) + `","e":"AQAB"}`)
}

// TestParseJWKRSABoundIgnoresGoJoseGlobal pins that the 4096-bit RSA bound
// of a remote JWK Set is the package's own: it holds when the application
// raises go-jose's process-wide jose.MaxRSAModulusBits. Not parallel: it
// mutates that global, and parallel tests only start once the sequential
// ones are done.
func TestParseJWKRSABoundIgnoresGoJoseGlobal(t *testing.T) {
	saved := jose.MaxRSAModulusBits
	jose.MaxRSAModulusBits = 8192

	t.Cleanup(func() { jose.MaxRSAModulusBits = saved })

	for bits, usable := range map[uint]bool{2048: true, 4096: true, 4097: false, 8192: false} {
		_, ok := parseJWK(rsaJWKOfBits(bits))
		assert.Equal(t, usable, ok, "%d bits", bits)
	}
}
