// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec_test

import (
	"context"
	"testing"
	"time"

	josejson "github.com/go-jose/go-jose/v4/json"
	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/stretchr/testify/require"
)

// FuzzVerifyToken feeds arbitrary strings to both entry points: no panic,
// and nothing over the size bound is ever accepted.
func FuzzVerifyToken(f *testing.F) {
	priv, pub := genECDSA(f)
	signer := mustSigner(f, priv)

	tok, err := signer.Sign(context.Background(), jwtsec.StandardClaims{Subject: "a", ExpiresAt: jwtsec.NewNumericDate(time.Now().Add(time.Hour))})
	require.NoError(f, err)

	for _, seed := range []string{tok, "eyJhbGciOiJub25lIn0.e30.", "..", "a.b.c.d", " " + tok, tok + "=", hostileHeader(2 << 10)} {
		f.Add(seed)
	}

	keys := []jwtsec.PublicKey{pub}
	v := jwtsec.NewVerifier(jwtsec.NewStaticJWKS(keys), jwtsec.WithType("JWT"))

	f.Fuzz(func(t *testing.T, s string) {
		if _, err := v.Verify(context.Background(), s, nil); err == nil {
			require.LessOrEqual(t, len(s), jwtsec.DefaultMaxTokenSize)
		}

		_, _ = jwtsec.VerifySignature(context.Background(), s, keys)
	})
}

// FuzzVerifyClaims signs arbitrary header and payload bytes with a trusted
// key, exercising everything behind the signature. Invariants of an
// accepted token: a header without jwk, x5c, jku or x5u, a JSON object
// payload, an exp in the future, a nbf not in the future, and a Subject
// equal to the exact "sub" member — as go-jose's case-sensitive decoder
// reads it — whatever case variants sit around it.
func FuzzVerifyClaims(f *testing.F) {
	priv, pub := genECDSA(f)
	now := time.Unix(1_800_000_000, 0)
	v := jwtsec.NewVerifier(jwtsec.NewStaticJWKS([]jwtsec.PublicKey{pub}), jwtsec.WithClock(newFixedClock(now)))

	for _, seed := range [][2]string{
		{`{"alg":"ES256","kid":"ec-1"}`, `{"sub":"a","exp":1900000000}`},
		{`{"alg":"ES256","kid":"ec-1","typ":"JWT"}`, `{"sub":"a","exp":1e300,"nbf":-1e300,"aud":["x",null]}`},
		{`{"alg":"ES256","kid":"ec-1","crit":["b64"],"b64":false}`, `{"exp":-62135596800}`},
		{`{"alg":"ES256","kid":"ec-1"}`, `{"sub":"a","Sub":"b","exp":1900000000}`},
		{`{"alg":"ES256","kid":"ec-1"}`, `{"SUB":"b","exp":1900000000,"nbf":null}`},
		{`{"alg":"ES256","kid":"ec-1","jwk":{"kty":"EC","crv":"P-256","x":"AQ","y":"AQ"},"x5u":"https://x"}`, `{"sub":"a","exp":1900000000}`},
	} {
		f.Add(seed[0], seed[1])
	}

	f.Fuzz(func(t *testing.T, head, payload string) {
		std, err := v.Verify(context.Background(), forge(t, jwtsec.ES256, priv.Key, head, payload), nil)
		if err != nil {
			return
		}

		var header map[string]josejson.RawMessage
		require.NoError(t, josejson.Unmarshal([]byte(head), &header), "an accepted header is one object")

		for _, name := range []string{"jwk", "x5c", "jku", "x5u"} {
			require.NotContains(t, header, name, "accepted a key-bearing header: %s", head)
		}

		var members map[string]josejson.RawMessage
		require.NoError(t, josejson.Unmarshal([]byte(payload), &members), "an accepted payload is one object")

		require.NotNil(t, std.ExpiresAt)
		require.True(t, now.Before(std.ExpiresAt.Time()), "accepted an expired token: %s", payload)

		if std.NotBefore != nil {
			require.False(t, now.Before(std.NotBefore.Time()), "accepted a token before nbf: %s", payload)
		}

		var sub string
		if raw, ok := members["sub"]; ok {
			require.NoError(t, josejson.Unmarshal(raw, &sub))
		}

		require.Equal(t, sub, std.Subject, "the subject is the exact sub member: %s", payload)
	})
}

// FuzzNumericDate checks that decoding never panics and that every
// accepted date is in range and re-encodes.
func FuzzNumericDate(f *testing.F) {
	for _, seed := range []string{`1`, `1.5`, `"x"`, `null`, `-1`, `253402300799`, `1e400`, `0x10`, `-0`} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, b []byte) {
		n := jwtsec.NumericDate(time.Unix(0, 0)) // null leaves it unchanged
		if n.UnmarshalJSON(b) != nil {
			return
		}

		sec := n.Time().Unix()
		require.GreaterOrEqual(t, sec, int64(0))
		require.LessOrEqual(t, sec, int64(253402300799))

		_, err := n.MarshalJSON()
		require.NoError(t, err)

		var a jwtsec.Audience
		_ = a.UnmarshalJSON(b)
	})
}
