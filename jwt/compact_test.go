// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec_test

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hyperscale-stack/security"
	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// verifyBoth runs token through a Verifier and VerifySignature built on the
// same keys and allow-list, and returns both errors.
func verifyBoth(t *testing.T, keys []jwtsec.PublicKey, token string, allowed ...jwtsec.Algorithm) (error, error) {
	t.Helper()

	opts := []jwtsec.Option{}
	if len(allowed) > 0 {
		opts = append(opts, jwtsec.WithAllowedAlgorithms(allowed...))
	}

	_, errV := jwtsec.NewVerifier(jwtsec.NewStaticJWKS(keys), opts...).Verify(context.Background(), token, nil)
	_, errS := jwtsec.VerifySignature(context.Background(), token, keys, allowed...)

	return errV, errS
}

// padded returns a valid ES256 token whose payload carries a pad claim of n
// bytes.
func padded(t *testing.T, priv jwtsec.PrivateKey, n int) string {
	t.Helper()

	payload := fmt.Sprintf(`{"sub":"alice","exp":%d,"pad":%q}`, in(time.Hour), strings.Repeat("p", n))

	return forge(t, jwtsec.ES256, priv.Key, header(jwtsec.ES256, "ec-1"), payload)
}

// paddedTo returns a valid ES256 token of at most size bytes and at least
// size-8.
func paddedTo(t *testing.T, priv jwtsec.PrivateKey, size int) string {
	t.Helper()

	n := (size - 200) * 3 / 4

	for {
		tok := padded(t, priv, n)

		switch {
		case len(tok) > size:
			n -= (len(tok)-size)*3/4 + 1
		case len(tok) < size-8:
			n += (size - len(tok)) * 3 / 4
		default:
			return tok
		}
	}
}

// hostileHeader is the audit's amplification token: a header of about
// size bytes of small members (JWT-02 probe), never validly signed.
func hostileHeader(size int) string {
	var b strings.Builder

	b.WriteString(`{"alg":"ES256","kid":"ec-1",`)

	for i := 0; b.Len() < size; i++ {
		b.WriteString(`"m` + strconv.Itoa(i) + `":[1],`)
	}

	b.WriteString(`"z":1}`)

	return b64.EncodeToString([]byte(b.String())) + "." + b64.EncodeToString([]byte(`{"sub":"x"}`)) + "." + strings.Repeat("A", 86)
}

// TestVerifyRefusesOversizedTokensBeforeParsing pins the size bound (audit
// JWT-02): a token longer than the bound is refused before any decoding —
// even a validly signed one — and the bound is configurable.
func TestVerifyRefusesOversizedTokensBeforeParsing(t *testing.T) {
	t.Parallel()

	priv, pub := genECDSA(t)
	keys := []jwtsec.PublicKey{pub}
	v := jwtsec.NewVerifier(jwtsec.NewStaticJWKS(keys))

	under := paddedTo(t, priv, jwtsec.DefaultMaxTokenSize)
	require.LessOrEqual(t, len(under), jwtsec.DefaultMaxTokenSize)

	_, err := v.Verify(context.Background(), under, nil)
	require.NoError(t, err, "a token under the default bound is accepted")

	over := paddedTo(t, priv, jwtsec.DefaultMaxTokenSize+16)
	require.Greater(t, len(over), jwtsec.DefaultMaxTokenSize)

	errV, errS := verifyBoth(t, keys, over)
	require.ErrorIs(t, errV, jwtsec.ErrMalformedToken, "a validly signed token over the bound is refused")
	require.ErrorIs(t, errS, jwtsec.ErrMalformedToken)

	// The bound is exact and configurable.
	tok := padded(t, priv, 100)

	_, err = jwtsec.NewVerifier(jwtsec.NewStaticJWKS(keys), jwtsec.WithMaxTokenSize(len(tok))).Verify(context.Background(), tok, nil)
	require.NoError(t, err, "a token of exactly the bound is accepted")

	_, err = jwtsec.NewVerifier(jwtsec.NewStaticJWKS(keys), jwtsec.WithMaxTokenSize(len(tok)-1)).Verify(context.Background(), tok, nil)
	require.ErrorIs(t, err, jwtsec.ErrMalformedToken, "one byte over the bound is refused")

	// The audit's ~1 MB hostile header is refused without reaching go-jose.
	errV, errS = verifyBoth(t, keys, hostileHeader(1<<20))
	for _, err := range []error{errV, errS} {
		require.ErrorIs(t, err, jwtsec.ErrMalformedToken)
		assert.NotContains(t, err.Error(), "go-jose")
		assert.Less(t, len(err.Error()), 200)
	}
}

func TestWithMaxTokenSizePanicsBelowOne(t *testing.T) {
	t.Parallel()

	assert.Panics(t, func() { jwtsec.WithMaxTokenSize(0) })
	assert.Panics(t, func() { jwtsec.WithMaxTokenSize(-1) })
	assert.NotPanics(t, func() { jwtsec.WithMaxTokenSize(1) })
}

// base64URLAlphabet is the alphabet of RFC 4648 §5.
const base64URLAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// TestVerifyRefusesNonCanonicalEncodings pins RFC 7515 §2 / RFC 7519 §7.2
// steps 3 and 9 (no whitespace or other characters) and RFC 4648 §3.5
// (decoders MAY reject non-zero pad bits): the audit's 33 encodings of one
// token (JWT-I1) are refused, so a token has a single encoding.
func TestVerifyRefusesNonCanonicalEncodings(t *testing.T) {
	t.Parallel()

	priv, pub := genECDSA(t)
	keys := []jwtsec.PublicKey{pub}

	var tok string

	// A token whose three segments all end in a partial quantum.
	for i := 0; ; i++ {
		tok = padded(t, priv, i)

		parts := strings.Split(tok, ".")
		if len(parts[0])%4 != 0 && len(parts[1])%4 != 0 && len(parts[2])%4 != 0 {
			break
		}
	}

	errV, errS := verifyBoth(t, keys, tok)
	require.NoError(t, errV, "the canonical token verifies")
	require.NoError(t, errS)

	parts := strings.Split(tok, ".")
	variants := 0

	for seg := range parts {
		s := parts[seg]

		for _, c := range base64URLAlphabet {
			if byte(c) == s[len(s)-1] {
				continue
			}

			mut := append([]string(nil), parts...)
			mut[seg] = s[:len(s)-1] + string(c)
			cand := strings.Join(mut, ".")

			// Only the variants a lenient decoder reads as the same bytes
			// matter: they would verify without the canonical check.
			if decodedEqual(s, mut[seg]) {
				variants++

				errV, errS := verifyBoth(t, keys, cand)
				require.ErrorIs(t, errV, jwtsec.ErrMalformedToken, "segment %d variant %q", seg, c)
				require.ErrorIs(t, errS, jwtsec.ErrMalformedToken)
			}
		}
	}

	require.Positive(t, variants, "non-canonical variants exist for this token")

	for name, cand := range map[string]string{
		"padding":            parts[0] + "==." + parts[1] + "." + parts[2],
		"leading space":      " " + tok,
		"trailing newline":   tok + "\n",
		"inner CRLF":         parts[0] + "\r\n." + parts[1] + "." + parts[2],
		"standard alphabet":  strings.ReplaceAll(strings.ReplaceAll(tok, "-", "+"), "_", "/"),
		"two segments":       parts[0] + "." + parts[1],
		"four segments":      tok + ".AAAA",
		"empty header":       "." + parts[1] + "." + parts[2],
		"empty payload":      parts[0] + ".." + parts[2],
		"impossible length":  tok + "AAA",
		"JSON serialization": `{"payload":"` + parts[1] + `"}`,
	} {
		if cand == tok {
			continue // e.g. no - or _ in this token for "standard alphabet"
		}

		errV, errS := verifyBoth(t, keys, cand)
		require.ErrorIs(t, errV, jwtsec.ErrMalformedToken, name)
		require.ErrorIs(t, errS, jwtsec.ErrMalformedToken, name)
	}
}

// decodedEqual reports whether two base64url segments decode to the same
// bytes under a lenient decoder (non-zero pad bits ignored).
func decodedEqual(a, b string) bool {
	da, errA := b64.DecodeString(a)
	db, errB := b64.DecodeString(b)

	return errA == nil && errB == nil && string(da) == string(db)
}

// TestVerifyRefusesInvalidHeaders pins RFC 7519 §7.2 step 4 (the header is
// a UTF-8 JSON object) and RFC 7515 §4 (unique parameter names): the
// header obeys the same strict JSON rules as the claims (review F13).
func TestVerifyRefusesInvalidHeaders(t *testing.T) {
	t.Parallel()

	priv, pub := genECDSA(t)
	keys := []jwtsec.PublicKey{pub}
	payload := fmt.Sprintf(`{"sub":"alice","exp":%d}`, in(time.Hour))

	for name, h := range map[string]string{
		"invalid UTF-8 in kid":       "{\"alg\":\"ES256\",\"kid\":\"ec-1\xff\"}",
		"lone surrogate in kid":      `{"alg":"ES256","kid":"ec-1` + esc("d800") + `"}`,
		"duplicate alg":              `{"alg":"ES256","kid":"ec-1","alg":"ES256"}`,
		"case variant of alg":        `{"alg":"ES256","kid":"ec-1","ALG":"none"}`,
		"escaped duplicate of kid":   `{"alg":"ES256","kid":"ec-1","k` + esc("0069") + `d":"ec-1"}`,
		"not an object":              `["ES256"]`,
		"trailing data":              `{"alg":"ES256","kid":"ec-1"} {}`,
		"nested beyond depth 32":     `{"alg":"ES256","kid":"ec-1","x":` + strings.Repeat("[", 32) + strings.Repeat("]", 32) + `}`,
		"kid of the wrong JSON type": `{"alg":"ES256","kid":["` + strings.Repeat("k", 5000) + `"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			errV, errS := verifyBoth(t, keys, forge(t, jwtsec.ES256, priv.Key, h, payload))
			require.ErrorIs(t, errV, jwtsec.ErrMalformedToken)
			require.ErrorIs(t, errS, jwtsec.ErrMalformedToken)
			assert.Less(t, len(errV.Error()), 400, "no raw header value is echoed")
			assert.Less(t, len(errS.Error()), 400)
		})
	}
}

// TestVerifyRefusesCritAndB64 pins RFC 7515 §4.1.11 (a JWS whose crit
// lists an extension the recipient does not support is invalid; crit is
// never an empty list), RFC 7797 §6/§7 (b64 always comes with crit; a JWT
// MUST NOT use b64 false) and RFC 7519 §7.2 step 5: this package
// implements no JWS extension, so crit and b64 are refused whatever their
// value, null included (audit JWT-I2, review F14).
func TestVerifyRefusesCritAndB64(t *testing.T) {
	t.Parallel()

	priv, pub := genECDSA(t)
	keys := []jwtsec.PublicKey{pub}
	payload := fmt.Sprintf(`{"sub":"alice","exp":%d}`, in(time.Hour))

	headers := map[string]string{
		"crit empty list":          `{"alg":"ES256","kid":"ec-1","crit":[]}`,
		"crit b64 without b64":     `{"alg":"ES256","kid":"ec-1","crit":["b64"]}`,
		"crit exp":                 `{"alg":"ES256","kid":"ec-1","crit":["exp"],"exp":1}`,
		"crit registered name":     `{"alg":"ES256","kid":"ec-1","crit":["kid"]}`,
		"crit not an array":        `{"alg":"ES256","kid":"ec-1","crit":"b64"}`,
		"crit null":                `{"alg":"ES256","kid":"ec-1","crit":null}`,
		"b64 true without crit":    `{"alg":"ES256","kid":"ec-1","b64":true}`,
		"b64 false without crit":   `{"alg":"ES256","kid":"ec-1","b64":false}`,
		"b64 null":                 `{"alg":"ES256","kid":"ec-1","b64":null}`,
		"crit b64 with b64 true":   `{"alg":"ES256","kid":"ec-1","crit":["b64"],"b64":true}`,
		"crit b64 with b64 false":  `{"alg":"ES256","kid":"ec-1","crit":["b64"],"b64":false}`,
		"crit b64, b64 not a bool": `{"alg":"ES256","kid":"ec-1","crit":["b64"],"b64":"false"}`,
	}

	for name, h := range headers {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			errV, errS := verifyBoth(t, keys, forge(t, jwtsec.ES256, priv.Key, h, payload))
			require.ErrorIs(t, errV, jwtsec.ErrMalformedToken)
			require.ErrorIs(t, errS, jwtsec.ErrMalformedToken)
		})
	}

	// A genuine RFC 7797 b64:false JWS — signed over the raw payload — is
	// not a JWT (audit probe P9: it verified and its claims were trusted).
	h := `{"alg":"ES256","kid":"ec-1","crit":["b64"],"b64":false}`
	input := b64.EncodeToString([]byte(h)) + "." + payload
	sig := signInput(t, jwtsec.ES256, priv.Key, []byte(input))
	tok := b64.EncodeToString([]byte(h)) + "." + b64.EncodeToString([]byte(payload)) + "." + b64.EncodeToString(sig)

	errV, errS := verifyBoth(t, keys, tok)
	require.ErrorIs(t, errV, jwtsec.ErrMalformedToken)
	require.ErrorIs(t, errS, jwtsec.ErrMalformedToken)
}

// TestVerifyReportsDisallowedAlgorithms pins that an algorithm outside the
// allow-list — HMAC under the default list included — is refused with
// ErrAlgorithmNotAllowed, by both entry points, before any key is used.
// (go-jose refused it first and the error surfaced as ErrMalformedToken,
// so ErrAlgorithmNotAllowed was unreachable.)
func TestVerifyReportsDisallowedAlgorithms(t *testing.T) {
	t.Parallel()

	secret := []byte(strings.Repeat("s", 32))
	hmacKey := jwtsec.PublicKey{KeyID: "h", Algorithm: jwtsec.HS256, Key: secret}
	priv, pub := genECDSA(t)
	payload := fmt.Sprintf(`{"sub":"alice","exp":%d}`, in(time.Hour))

	cases := []struct {
		name    string
		token   string
		keys    []jwtsec.PublicKey
		allowed []jwtsec.Algorithm
		alg     string
	}{
		{"HS256 under the default list", forge(t, jwtsec.HS256, secret, header(jwtsec.HS256, "h"), payload), []jwtsec.PublicKey{hmacKey}, nil, "HS256"},
		{"none", b64.EncodeToString([]byte(`{"alg":"none","kid":"ec-1"}`)) + "." + b64.EncodeToString([]byte(payload)) + ".", []jwtsec.PublicKey{pub}, nil, "none"},
		{"ES256 when only EdDSA is allowed", forge(t, jwtsec.ES256, priv.Key, header(jwtsec.ES256, "ec-1"), payload), []jwtsec.PublicKey{pub}, []jwtsec.Algorithm{jwtsec.EdDSA}, "ES256"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			errV, errS := verifyBoth(t, tc.keys, tc.token, tc.allowed...)

			for _, err := range []error{errV, errS} {
				require.ErrorIs(t, err, jwtsec.ErrAlgorithmNotAllowed)
				require.ErrorIs(t, err, security.ErrInvalidCredentials)

				got, ok := jwtsec.AsAlgorithmName(err)
				require.True(t, ok)
				assert.Equal(t, tc.alg, got)
			}
		})
	}
}

// TestVerifyClipsHeaderValuesInErrorsAndSpans pins that no token-supplied
// value reaches an error or a span unbounded (audit JWT-I7, JWT-02): the
// kid, the alg and the parser's own messages are clipped — a number
// literal the standard library quoted whole included (review F1). Not
// parallel: it installs the recording tracer provider.
func TestVerifyClipsHeaderValuesInErrorsAndSpans(t *testing.T) {
	priv, pub := genECDSA(t)
	other, _ := genECDSA(t)
	v := jwtsec.NewVerifier(jwtsec.NewStaticJWKS([]jwtsec.PublicKey{pub}))
	payload := fmt.Sprintf(`{"sub":"alice","exp":%d}`, in(time.Hour))
	longKid := strings.Repeat("k", 10<<10)
	longAlg := strings.Repeat("A", 5<<10)
	// An unknown header member holding an 11 000-digit number: valid JSON,
	// which go-jose refuses — it decodes unknown header values into float64.
	longNumber := forge(t, jwtsec.ES256, other.Key, `{"alg":"ES256","kid":"ec-1","x":1`+strings.Repeat("0", 11_000)+`}`, payload)

	var errKid, errAlg, errNumber, errNumberSig error

	spans := record(func() {
		_, errKid = v.Verify(context.Background(), forge(t, jwtsec.ES256, priv.Key, header(jwtsec.ES256, longKid), payload), nil)
		_, errAlg = v.Verify(context.Background(), forge(t, jwtsec.ES256, priv.Key, `{"alg":"`+longAlg+`","kid":"ec-1"}`, payload), nil)
		_, errNumber = v.Verify(context.Background(), longNumber, nil)
		_, errNumberSig = jwtsec.VerifySignature(context.Background(), longNumber, []jwtsec.PublicKey{pub})
	})

	for _, err := range []error{errNumber, errNumberSig} {
		require.ErrorIs(t, err, jwtsec.ErrMalformedToken)
		assert.Less(t, len(err.Error()), 400, "the number literal is not echoed")
	}

	require.ErrorIs(t, errKid, jwtsec.ErrInvalidSignature, "unknown kid")
	assert.Less(t, len(errKid.Error()), 400)
	assert.Contains(t, errKid.Error(), "…", "the kid is clipped, not dropped")

	require.ErrorIs(t, errAlg, jwtsec.ErrAlgorithmNotAllowed)
	assert.Less(t, len(errAlg.Error()), 400)

	alg, ok := jwtsec.AsAlgorithmName(errAlg)
	require.True(t, ok)
	assert.LessOrEqual(t, len(alg), 128+len("…"))

	verifies := named(spans, "jwtsec.Verifier.Verify")
	require.Len(t, verifies, 3)

	for _, s := range append(verifies, named(spans, "jwtsec.VerifySignature")...) {
		assert.LessOrEqual(t, len(s.attr("jwt.kid")), 128+len("…"))
		assert.LessOrEqual(t, len(s.attr("jwt.alg")), 128+len("…"))

		for _, e := range s.errs {
			assert.Less(t, len(e), 400, "recorded errors are clipped")
		}
	}
}

// BenchmarkVerifyHostileHeader documents the pre-authentication cost of
// the worst header within the default bound (JWT-02: ~1 MB cost ~100 MiB
// before the bound).
func BenchmarkVerifyHostileHeader(b *testing.B) {
	_, pub := genECDSA(b)
	v := jwtsec.NewVerifier(jwtsec.NewStaticJWKS([]jwtsec.PublicKey{pub}))

	for _, size := range []int{1 << 10, jwtsec.DefaultMaxTokenSize * 3 / 4, 1 << 20} {
		tok := hostileHeader(size)

		b.Run(strconv.Itoa(len(tok)), func(b *testing.B) {
			b.ReportAllocs()

			for b.Loop() {
				_, _ = v.Verify(context.Background(), tok, nil)
			}
		})
	}
}
