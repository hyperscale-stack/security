// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient

import (
	"encoding/base64"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCheckRawHeaderRefusesBeforeParsing bounds the cost of refusing the
// advisory header of GHSA-mgcc-cww5-fp2q (audit F-02) — an RSA private JWK
// with a 16 384-bit prime, about 41 000 allocations and seconds of CPU in
// go-jose v4.1.5 — to the strict header decode. Not parallel: AllocsPerRun
// counts the allocations of every goroutine, and parallel tests only start
// once the sequential ones are done.
func TestCheckRawHeaderRefusesBeforeParsing(t *testing.T) {
	enc := func(x *big.Int) string { return base64.RawURLEncoding.EncodeToString(x.Bytes()) }

	one := big.NewInt(1)
	n := new(big.Int).Add(new(big.Int).Lsh(one, 2048), one)
	p := new(big.Int).Add(new(big.Int).Lsh(one, 16383), one)
	header := fmt.Sprintf(`{"alg":"RS256","kid":"rsa-1","jwk":{"kty":"RSA","n":%q,"e":"AQAB","d":"Aw","p":%q,"q":"Aw"}}`, enc(n), enc(p))
	raw := base64.RawURLEncoding.EncodeToString([]byte(header)) + ".e30.c2ln"

	var err error

	allocs := testing.AllocsPerRun(1, func() { err = checkRawHeader(raw) })
	t.Logf("%.0f allocations", allocs)

	require.ErrorIs(t, err, ErrIDTokenMalformed)
	assert.Contains(t, err.Error(), `unsupported "jwk" header parameter`)
	assert.LessOrEqual(t, allocs, float64(1000))
}
