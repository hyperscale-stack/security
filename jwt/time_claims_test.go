// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// timeFixture verifies payloads signed by one key against a fixed clock.
type timeFixture struct {
	t    *testing.T
	priv jwtsec.PrivateKey
	keys jwtsec.JWKSProvider
	now  time.Time
}

func newTimeFixture(t *testing.T) timeFixture {
	t.Helper()

	priv, pub := genECDSA(t)

	return timeFixture{t: t, priv: priv, keys: jwtsec.NewStaticJWKS([]jwtsec.PublicKey{pub}), now: time.Unix(1_800_000_000, 0)}
}

func (f timeFixture) verify(payload string, opts ...jwtsec.Option) (*jwtsec.StandardClaims, error) {
	f.t.Helper()

	opts = append([]jwtsec.Option{jwtsec.WithClock(newFixedClock(f.now))}, opts...)

	return jwtsec.NewVerifier(f.keys, opts...).Verify(context.Background(),
		forge(f.t, jwtsec.ES256, f.priv.Key, header(jwtsec.ES256, "ec-1"), payload), nil)
}

// TestVerifyEnforcesExpAtTheBoundary pins RFC 7519 §4.1.4 and RFC 9068 §4:
// "the current date/time MUST be before the expiration date/time" — the
// token is expired from now == exp + skew on (audit JWT-I3: now == exp
// was accepted).
func TestVerifyEnforcesExpAtTheBoundary(t *testing.T) {
	t.Parallel()

	f := newTimeFixture(t)

	for _, skew := range []time.Duration{0, 30 * time.Second} {
		exp := f.now.Add(-skew).Unix()

		_, err := f.verify(fmt.Sprintf(`{"sub":"a","exp":%d}`, exp), jwtsec.WithClockSkew(skew))
		require.ErrorIs(t, err, jwtsec.ErrTokenExpired, "now == exp + skew (%s) is expired", skew)

		_, err = f.verify(fmt.Sprintf(`{"sub":"a","exp":%d}`, exp+1), jwtsec.WithClockSkew(skew))
		require.NoError(t, err, "one second before exp + skew (%s) is valid", skew)
	}

	// Fractional NumericDates are compared exactly.
	_, err := f.verify(fmt.Sprintf(`{"sub":"a","exp":%d.5}`, f.now.Unix()))
	require.NoError(t, err, "now is before exp = now + 0.5 s")

	f.now = f.now.Add(500 * time.Millisecond)

	_, err = f.verify(fmt.Sprintf(`{"sub":"a","exp":%d.5}`, f.now.Unix()-1))
	require.ErrorIs(t, err, jwtsec.ErrTokenExpired, "now == exp to the nanosecond")
}

// TestVerifyNotBeforeAndIssuedAtBoundaries pins RFC 7519 §4.1.5 (valid from
// nbf on, inclusive) and the iat sanity check (not issued in the future),
// both with the clock skew.
func TestVerifyNotBeforeAndIssuedAtBoundaries(t *testing.T) {
	t.Parallel()

	f := newTimeFixture(t)
	exp := f.now.Add(time.Hour).Unix()

	for _, skew := range []time.Duration{0, 30 * time.Second} {
		edge := f.now.Add(skew).Unix()

		_, err := f.verify(fmt.Sprintf(`{"sub":"a","exp":%d,"nbf":%d}`, exp, edge), jwtsec.WithClockSkew(skew))
		require.NoError(t, err, "now == nbf - skew (%s) is valid", skew)

		_, err = f.verify(fmt.Sprintf(`{"sub":"a","exp":%d,"nbf":%d}`, exp, edge+1), jwtsec.WithClockSkew(skew))
		require.ErrorIs(t, err, jwtsec.ErrTokenNotYetValid, "nbf one second beyond the skew (%s)", skew)

		_, err = f.verify(fmt.Sprintf(`{"sub":"a","exp":%d,"iat":%d}`, exp, edge), jwtsec.WithClockSkew(skew))
		require.NoError(t, err, "iat == now + skew (%s) is valid", skew)

		_, err = f.verify(fmt.Sprintf(`{"sub":"a","exp":%d,"iat":%d}`, exp, edge+1), jwtsec.WithClockSkew(skew))
		require.ErrorIs(t, err, jwtsec.ErrTokenNotYetValid, "iat one second beyond the skew (%s)", skew)
	}
}

// TestVerifyRefusesOutOfRangeNumericDates pins RFC 7519 §2: a NumericDate
// is a number of seconds since the epoch; the package accepts 1970 to
// year 9999. A year-1 exp — what a zero time.Time marshalled to — no
// longer disables expiry (audit JWT-07), and huge or negative values no
// longer wrap around (JWT-I4).
func TestVerifyRefusesOutOfRangeNumericDates(t *testing.T) {
	t.Parallel()

	f := newTimeFixture(t)
	exp := f.now.Add(time.Hour).Unix()

	for name, payload := range map[string]string{
		"exp year 1 (zero time.Time)": `{"sub":"a","exp":-62135596800}`,
		"exp -1":                      `{"sub":"a","exp":-1}`,
		"exp year 10000":              `{"sub":"a","exp":253402300800}`,
		"exp 9.3e18":                  `{"sub":"a","exp":9.3e18}`,
		"exp 1e19":                    `{"sub":"a","exp":1e19}`,
		"exp max int64":               `{"sub":"a","exp":9223372036854775807}`,
		"exp beyond float64":          `{"sub":"a","exp":1e400}`,
		"nbf 1e19":                    fmt.Sprintf(`{"sub":"a","exp":%d,"nbf":1e19}`, exp),
		"nbf -1e300":                  fmt.Sprintf(`{"sub":"a","exp":%d,"nbf":-1e300}`, exp),
		"iat -1":                      fmt.Sprintf(`{"sub":"a","exp":%d,"iat":-1}`, exp),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			for _, opts := range [][]jwtsec.Option{nil, {jwtsec.WithOptionalExpiry()}} {
				std, err := f.verify(payload, opts...)
				require.ErrorIs(t, err, jwtsec.ErrMalformedToken)
				assert.Nil(t, std)
			}
		})
	}

	_, err := f.verify(`{"sub":"a","exp":0}`)
	require.ErrorIs(t, err, jwtsec.ErrTokenExpired, "exp 0 is 1970: in range, expired")

	_, err = f.verify(`{"sub":"a","exp":253402300799}`)
	require.NoError(t, err, "9999-12-31T23:59:59Z is the last accepted date")
}

func TestWithClockSkewIsBounded(t *testing.T) {
	t.Parallel()

	assert.Panics(t, func() { jwtsec.WithClockSkew(-time.Nanosecond) })
	assert.Panics(t, func() { jwtsec.WithClockSkew(jwtsec.MaxClockSkew + time.Nanosecond) })
	assert.Panics(t, func() { jwtsec.WithClockSkew(100 * 365 * 24 * time.Hour) }, "audit JWT-I4: 100 years")
	assert.NotPanics(t, func() { jwtsec.WithClockSkew(0) })
	assert.NotPanics(t, func() { jwtsec.WithClockSkew(jwtsec.MaxClockSkew) })
	assert.Equal(t, 5*time.Minute, jwtsec.MaxClockSkew)
}

func TestNumericDateJSON(t *testing.T) {
	t.Parallel()

	// null is a no-op (the encoding/json convention for Unmarshalers).
	n := jwtsec.NumericDate(time.Unix(5, 0))
	require.NoError(t, n.UnmarshalJSON([]byte(`null`)))
	assert.Equal(t, time.Unix(5, 0), n.Time())

	require.NoError(t, n.UnmarshalJSON([]byte(`1.5`)))
	assert.Equal(t, time.Unix(1, 5e8).UTC(), n.Time())

	for _, bad := range []string{`"1700000000"`, `true`, `[1]`, `{}`, `-1`, `253402300800`, `1e400`, `NaN`, ``, `0x1p4`, `01`, `1.`, `-`, `1e`} {
		assert.Error(t, n.UnmarshalJSON([]byte(bad)), bad)
	}

	out, err := json.Marshal(jwtsec.NewNumericDate(time.Unix(253402300799, 0)))
	require.NoError(t, err)
	assert.Equal(t, "253402300799", string(out))

	out, err = json.Marshal(jwtsec.NewNumericDate(time.Unix(0, 0)))
	require.NoError(t, err)
	assert.Equal(t, "0", string(out))

	for name, d := range map[string]time.Time{
		"zero time.Time": {},
		"before 1970":    time.Unix(-1, 0),
		"after 9999":     time.Unix(253402300800, 0),
	} {
		_, err := json.Marshal(jwtsec.NewNumericDate(d))
		assert.Error(t, err, name)

		_, err = json.Marshal(jwtsec.StandardClaims{ExpiresAt: jwtsec.NewNumericDate(d)})
		assert.Error(t, err, name)
	}
}

// TestSignerRefusesOutOfRangeDates pins that no signer emits the year-1
// exp a zero time.Time used to marshal to (audit JWT-07): nothing is
// signed, and the error is a signing-side one, not a credential failure.
func TestSignerRefusesOutOfRangeDates(t *testing.T) {
	t.Parallel()

	priv, _ := genECDSA(t)
	signer := mustSigner(t, priv)

	for name, claims := range map[string]jwtsec.StandardClaims{
		"zero exp":       {Subject: "a", ExpiresAt: jwtsec.NewNumericDate(time.Time{})},
		"zero iat":       {Subject: "a", ExpiresAt: jwtsec.NewNumericDate(time.Now().Add(time.Hour)), IssuedAt: jwtsec.NewNumericDate(time.Time{})},
		"pre-1970 nbf":   {Subject: "a", NotBefore: jwtsec.NewNumericDate(time.Unix(-10, 0))},
		"year 10000 exp": {Subject: "a", ExpiresAt: jwtsec.NewNumericDate(time.Unix(253402300800, 0))},
	} {
		tok, err := signer.Sign(context.Background(), claims)
		require.ErrorIs(t, err, jwtsec.ErrUnsignableClaims, name)
		assert.Empty(t, tok, name)
	}

	_, err := signer.Sign(context.Background(), map[string]any{"x": make(chan int)})
	require.ErrorIs(t, err, jwtsec.ErrUnsignableClaims, "claims that cannot be marshalled are unsignable")
}
