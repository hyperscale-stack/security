// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hyperscale-stack/security"
	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testIssuer = "https://as.example"

// customClaims is a caller claims type: StandardClaims plus private claims.
type customClaims struct {
	jwtsec.StandardClaims

	Role string `json:"role"`
	Ext  any    `json:"ext"`
}

// TestVerifyRefusesDuplicateAndCaseVariantClaimNames pins RFC 7519 §4
// (unique claim names) and §7.3/§10.1.1 (case-sensitive names): a claims
// set whose member names repeat — exactly, through an escape, or under
// Unicode case folding — is refused, so no decoder can read a smuggled
// "Sub", "EXP", "AUD" or "ſub" in place of the registered claim (audit
// JWT-01 probe P1).
func TestVerifyRefusesDuplicateAndCaseVariantClaimNames(t *testing.T) {
	t.Parallel()

	priv, pub := genECDSA(t)
	v := jwtsec.NewVerifier(jwtsec.NewStaticJWKS([]jwtsec.PublicKey{pub}),
		jwtsec.WithIssuer(testIssuer), jwtsec.WithAudience("api"))

	base := fmt.Sprintf(`"iss":%q,"aud":"api","exp":%d`, testIssuer, in(time.Hour))

	cases := map[string]string{
		"exact duplicate sub":             `{` + base + `,"sub":"alice","sub":"admin"}`,
		"escaped duplicate sub":           `{` + base + `,"sub":"alice","s` + esc("0075") + `b":"admin"}`,
		"escaped long s variant":          `{` + base + `,"sub":"alice","` + esc("017f") + `ub":"admin"}`,
		"escaped kelvin sign variant":     `{` + base + `,"sub":"a","kid":"x","` + esc("212a") + `id":"y"}`,
		"case variants of sub and scope":  `{` + base + `,"sub":"alice","scope":"read","Sub":"admin","SCOPE":"admin write"}`,
		"escaped case variant":            `{` + base + `,"sub":"a","` + esc("0053") + `ub":"b"}`,
		"case variant Sub":                `{` + base + `,"sub":"a","Sub":"b"}`,
		"long s (U+017F) variant of sub":  `{` + base + `,"sub":"alice","ſub":"admin"}`,
		"kelvin sign (U+212A) variant":    `{` + base + `,"sub":"alice","kid":"x","Kid":"y"}`,
		"nested duplicate":                `{` + base + `,"sub":"a","ext":{"role":"user","role":"admin"}}`,
		"nested case variant":             `{` + base + `,"sub":"a","ext":{"role":"user","ROLE":"admin"}}`,
		"case variant in an array object": `{` + base + `,"sub":"a","ext":[1,{"role":"user","Role":"admin"}]}`,
		"EXP extends an expired token": fmt.Sprintf(`{"iss":%q,"aud":"api","sub":"alice","exp":%d,"EXP":%d}`,
			testIssuer, in(-time.Hour), in(time.Hour)),
		"AUD smuggles the audience": fmt.Sprintf(`{"iss":%q,"aud":"other-api","sub":"alice","exp":%d,"AUD":"api"}`,
			testIssuer, in(time.Hour)),
	}

	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var out customClaims

			std, err := v.Verify(context.Background(), forge(t, jwtsec.ES256, priv.Key, header(jwtsec.ES256, "ec-1"), payload), &out)
			require.ErrorIs(t, err, jwtsec.ErrMalformedToken)
			require.ErrorIs(t, err, security.ErrInvalidCredentials)
			assert.Nil(t, std)
			assert.Equal(t, customClaims{}, out, "claimsOut is not written")
		})
	}
}

// TestVerifyDecodesClaimNamesCaseSensitively pins that a lone case variant
// is another, private claim (RFC 7519 §10.1.1): it never fills a registered
// claim, nor a tagged field of the caller's claims type.
func TestVerifyDecodesClaimNamesCaseSensitively(t *testing.T) {
	t.Parallel()

	priv, pub := genECDSA(t)
	v := jwtsec.NewVerifier(jwtsec.NewStaticJWKS([]jwtsec.PublicKey{pub}))

	var out customClaims

	payload := fmt.Sprintf(`{"exp":%d,"SUB":"admin","Role":"admin","Scope":"admin"}`, in(time.Hour))

	std, err := v.Verify(context.Background(), forge(t, jwtsec.ES256, priv.Key, header(jwtsec.ES256, "ec-1"), payload), &out)
	require.NoError(t, err)
	assert.Empty(t, std.Subject, "SUB is not sub")
	assert.Empty(t, std.Scope, "Scope is not scope")
	assert.Empty(t, out.Subject)
	assert.Empty(t, out.Role, "Role is not role")

	payload = fmt.Sprintf(`{"exp":%d,"sub":"alice","role":"user","ext":{"a":[1,2]}}`, in(time.Hour))

	std, err = v.Verify(context.Background(), forge(t, jwtsec.ES256, priv.Key, header(jwtsec.ES256, "ec-1"), payload), &out)
	require.NoError(t, err)
	assert.Equal(t, "alice", std.Subject)
	assert.Equal(t, "alice", out.Subject)
	assert.Equal(t, "user", out.Role)
	assert.Equal(t, map[string]any{"a": []any{float64(1), float64(2)}}, out.Ext)
}

// TestVerifyRefusesNonUTF8AndLoneSurrogateClaims pins RFC 8725 §3.7 and
// RFC 8259 §8.2: claims are UTF-8, and an unpaired surrogate escape —
// which decoders turn into U+FFFD, mapping distinct signed values to one —
// is refused.
func TestVerifyRefusesNonUTF8AndLoneSurrogateClaims(t *testing.T) {
	t.Parallel()

	priv, pub := genECDSA(t)
	v := jwtsec.NewVerifier(jwtsec.NewStaticJWKS([]jwtsec.PublicKey{pub}))

	for name, sub := range map[string]string{
		"lone high surrogate": `"` + esc("d800") + `"`,
		"lone low surrogate":  `"` + esc("dfff") + `"`,
		"high then text":      `"` + esc("d800") + `abc"`,
		"lone last high":      `"` + esc("dbff") + `"`,
		"high then non-low":   `"` + esc("d800") + esc("e000") + `"`,
		"invalid UTF-8":       "\"\xff\"",
		"overlong UTF-8":      "\"\xc0\xaf\"",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			payload := fmt.Sprintf(`{"sub":%s,"exp":%d}`, sub, in(time.Hour))

			_, err := v.Verify(context.Background(), forge(t, jwtsec.ES256, priv.Key, header(jwtsec.ES256, "ec-1"), payload), nil)
			require.ErrorIs(t, err, jwtsec.ErrMalformedToken)
		})
	}

	for pair, want := range map[string]string{
		esc("d83d") + esc("de00"): "\U0001F600",
		esc("d800") + esc("dc00"): "\U00010000",
		esc("dbff") + esc("dfff"): "\U0010FFFF",
	} {
		payload := fmt.Sprintf(`{"sub":"%s","exp":%d}`, pair, in(time.Hour))

		std, err := v.Verify(context.Background(), forge(t, jwtsec.ES256, priv.Key, header(jwtsec.ES256, "ec-1"), payload), nil)
		require.NoError(t, err, "a surrogate pair is valid: %s", pair)
		assert.Equal(t, want, std.Subject)
	}
}

// TestVerifyReadsLongNumbersWithoutEchoingThem pins review F1: a number
// literal too long for a float64 is valid JSON (RFC 8259 §6) — ignored in
// an unknown claim (RFC 7519 §4) — and a decoder refusing it for a field
// of claimsOut does not echo it whole.
func TestVerifyReadsLongNumbersWithoutEchoingThem(t *testing.T) {
	t.Parallel()

	priv, pub := genECDSA(t)
	v := jwtsec.NewVerifier(jwtsec.NewStaticJWKS([]jwtsec.PublicKey{pub}))
	payload := fmt.Sprintf(`{"sub":"alice","exp":%d,"n":1%s}`, in(time.Hour), strings.Repeat("0", 11_000))
	tok := forge(t, jwtsec.ES256, priv.Key, header(jwtsec.ES256, "ec-1"), payload)

	std, err := v.Verify(context.Background(), tok, nil)
	require.NoError(t, err, "an unknown claim is ignored, whatever its value")
	assert.Equal(t, "alice", std.Subject)

	var out struct {
		N int64 `json:"n"`
	}

	_, err = v.Verify(context.Background(), tok, &out)
	require.ErrorIs(t, err, jwtsec.ErrMalformedToken)
	assert.Less(t, len(err.Error()), 400, "the number literal is not echoed")
}

// TestVerifyRefusesNonObjectPayloads pins RFC 7519 §7.2 step 10: the claims
// set is one JSON object — whatever the expiry policy (audit JWT-I5).
func TestVerifyRefusesNonObjectPayloads(t *testing.T) {
	t.Parallel()

	priv, pub := genECDSA(t)
	keys := jwtsec.NewStaticJWKS([]jwtsec.PublicKey{pub})

	for name, payload := range map[string]string{
		"null":           `null`,
		"array":          `[]`,
		"string":         `"str"`,
		"number":         `123`,
		"empty":          ``,
		"two objects":    `{} {}`,
		"trailing data":  `{"a":1} x`,
		"nested too far": `{"a":` + strings.Repeat("[", 32) + strings.Repeat("]", 32) + `}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tok := forge(t, jwtsec.ES256, priv.Key, header(jwtsec.ES256, "ec-1"), payload)

			for _, v := range []jwtsec.Verifier{
				jwtsec.NewVerifier(keys),
				jwtsec.NewVerifier(keys, jwtsec.WithOptionalExpiry()),
			} {
				std, err := v.Verify(context.Background(), tok, nil)
				require.ErrorIs(t, err, jwtsec.ErrMalformedToken)
				assert.Nil(t, std)
			}
		})
	}
}

// TestVerifyRefusesMistypedRegisteredClaims pins RFC 7519 §4.1: exp, nbf
// and iat MUST be numbers, iss, sub and jti strings, aud a string or an
// array of strings — and scope a string (RFC 8693 §4.2). A null value is
// not an absent claim: "nbf": null must not disable the not-before check,
// nor "exp": null make a token immortal (review F8).
func TestVerifyRefusesMistypedRegisteredClaims(t *testing.T) {
	t.Parallel()

	priv, pub := genECDSA(t)
	v := jwtsec.NewVerifier(jwtsec.NewStaticJWKS([]jwtsec.PublicKey{pub}), jwtsec.WithOptionalExpiry())

	for name, member := range map[string]string{
		"exp null":           `"exp":null`,
		"nbf null":           `"nbf":null`,
		"iat null":           `"iat":null`,
		"exp string":         `"exp":"1700000000"`,
		"nbf bool":           `"nbf":true`,
		"iss null":           `"iss":null`,
		"iss number":         `"iss":1`,
		"sub null":           `"sub":null`,
		"sub bool":           `"sub":true`,
		"jti null":           `"jti":null`,
		"jti number":         `"jti":1`,
		"aud null":           `"aud":null`,
		"aud number":         `"aud":1`,
		"aud array of int":   `"aud":[1]`,
		"aud array w/ null":  `"aud":["api",null]`,
		"aud object":         `"aud":{"a":"b"}`,
		"scope null":         `"scope":null`,
		"scope array":        `"scope":["read"]`,
		"aud nested array":   `"aud":[["api"]]`,
		"exp array of dates": `"exp":[1]`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			std, err := v.Verify(context.Background(),
				forge(t, jwtsec.ES256, priv.Key, header(jwtsec.ES256, "ec-1"), `{"x":1,`+member+`}`), nil)
			require.ErrorIs(t, err, jwtsec.ErrMalformedToken)
			assert.Nil(t, std)
		})
	}

	std, err := v.Verify(context.Background(), forge(t, jwtsec.ES256, priv.Key, header(jwtsec.ES256, "ec-1"),
		fmt.Sprintf(`{"iss":"i","sub":"s","jti":"j","scope":"a b","aud":["x","y"],"exp":%d,"nbf":1.5,"iat":2}`, in(time.Hour))), nil)
	require.NoError(t, err, "well-typed registered claims are accepted")
	assert.Equal(t, jwtsec.Audience{"x", "y"}, std.Audience)
}

// unexportedPart is embedded by pointer below: go-jose's decoder (a fork
// of encoding/json from Go 1.6) panics on such a field.
type unexportedPart struct {
	X string `json:"x"`
}

type claimsWithUnexportedPointer struct {
	*unexportedPart

	Y string `json:"y"`
}

// TestVerifyRefusesClaimsTheDecoderCannotHold pins that a claims type the
// decoder cannot fill fails verification instead of panicking the server.
func TestVerifyRefusesClaimsTheDecoderCannotHold(t *testing.T) {
	t.Parallel()

	priv, pub := genECDSA(t)
	v := jwtsec.NewVerifier(jwtsec.NewStaticJWKS([]jwtsec.PublicKey{pub}))
	tok := forge(t, jwtsec.ES256, priv.Key, header(jwtsec.ES256, "ec-1"), fmt.Sprintf(`{"exp":%d,"x":"a","y":"b"}`, in(time.Hour)))

	var out claimsWithUnexportedPointer

	require.NotPanics(t, func() {
		_, err := v.Verify(context.Background(), tok, &out)
		require.ErrorIs(t, err, jwtsec.ErrMalformedToken)
	})

	var notAPointer customClaims

	_, err := v.Verify(context.Background(), tok, notAPointer)
	require.ErrorIs(t, err, jwtsec.ErrMalformedToken)
}
