// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// maxHeader is the bound on a decoded JOSE header: 4 KiB.
const maxHeader = 4 << 10

// headerOfSize returns a JOSE header naming ES256 and kid ec-1 of exactly
// size bytes.
func headerOfSize(t *testing.T, size int) string {
	t.Helper()

	h := `{"alg":"ES256","kid":"ec-1","x":""}`
	h = strings.Replace(h, `"x":""`, fmt.Sprintf(`"x":%q`, strings.Repeat("h", size-len(h))), 1)
	require.Len(t, h, size)

	return h
}

// TestVerifyBoundsTheJOSEHeader pins audit I-13: go-jose decodes a header
// into maps — 70 to 260 times its size, before checking the algorithm —
// so the pre-authentication cost grew with the token bound a caller set.
// The decoded header is now bounded to 4 KiB whatever the token bound:
// a validly signed token whose header is exactly 4096 bytes is accepted,
// one byte more is refused with ErrMalformedToken — by Verifier, under a
// raised WithMaxTokenSize too, and by VerifySignature.
func TestVerifyBoundsTheJOSEHeader(t *testing.T) {
	t.Parallel()

	priv, pub := genECDSA(t)
	keys := []jwtsec.PublicKey{pub}

	at := forge(t, jwtsec.ES256, priv.Key, headerOfSize(t, maxHeader), claimsPayload())
	errV, errS := verifyBoth(t, keys, at)
	require.NoError(t, errV, "a header of exactly 4 KiB")
	require.NoError(t, errS)

	over := forge(t, jwtsec.ES256, priv.Key, headerOfSize(t, maxHeader+1), claimsPayload())
	errV, errS = verifyBoth(t, keys, over)

	for _, err := range []error{errV, errS} {
		require.ErrorIs(t, err, jwtsec.ErrMalformedToken)
		assert.Contains(t, err.Error(), "header larger than 4096 bytes")
	}

	_, err := jwtsec.NewVerifier(jwtsec.NewStaticJWKS(keys), jwtsec.WithMaxTokenSize(1<<20)).
		Verify(context.Background(), over, nil)
	require.ErrorIs(t, err, jwtsec.ErrMalformedToken, "the header bound holds under a raised token bound")
}

// TestVerifyRefusesALargeHeaderWithoutDecodingIt: a hostile header over
// the bound — small members, the audit's amplification shape — is refused
// before anything decodes it: a handful of allocations, where go-jose
// allocates thousands. Not parallel: testing.AllocsPerRun refuses it.
func TestVerifyRefusesALargeHeaderWithoutDecodingIt(t *testing.T) {
	_, pub := genECDSA(t)
	v := jwtsec.NewVerifier(jwtsec.NewStaticJWKS([]jwtsec.PublicKey{pub}), jwtsec.WithMaxTokenSize(1<<20))
	tok := hostileHeader(64 << 10)

	_, err := v.Verify(context.Background(), tok, nil)
	require.ErrorIs(t, err, jwtsec.ErrMalformedToken)

	allocs := testing.AllocsPerRun(20, func() { _, _ = v.Verify(context.Background(), tok, nil) })
	assert.Less(t, allocs, 30.0, "refused before decoding")
}
