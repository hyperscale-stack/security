// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"strconv"
	"strings"
	"testing"

	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// keyVerbs are the fmt verbs a key is checked with. %p of a value is left
// out: fmt prints the fields of a value for that invalid verb before any
// method, which no type can redact.
var keyVerbs = []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%t", "%o", "%b", "%e", "%U", "%c"}

// keyRenderings renders v every way an application may print or log it:
// every verb, slog's text and JSON handlers, and encoding/json — of v and
// of a struct holding it, as a configuration does.
func keyRenderings(t *testing.T, v any) map[string]string {
	t.Helper()

	out := map[string]string{}

	for _, verb := range keyVerbs {
		out[verb] = fmt.Sprintf(verb, v)
		out["nested "+verb] = fmt.Sprintf(verb, struct{ Keys []any }{Keys: []any{v}})
	}

	var text, js strings.Builder

	slog.New(slog.NewTextHandler(&text, nil)).Info("key", "key", v)
	slog.New(slog.NewJSONHandler(&js, nil)).Info("key", "key", v)
	out["slog text"], out["slog JSON"] = text.String(), js.String()

	raw, err := json.Marshal(struct{ Keys []any }{Keys: []any{v}})
	require.NoError(t, err)

	out["encoding/json"] = string(raw)

	return out
}

// materialOf returns how the secret material of a key appears when fmt,
// slog or encoding/json print it.
func materialOf(key any) []string {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return []string{k.D.String(), fmt.Sprintf("%x", k.D)}
	case *ecdsa.PrivateKey:
		d, _ := k.Bytes()

		return []string{fmt.Sprintf("%x", d), new(big.Int).SetBytes(d).String()}
	case ed25519.PrivateKey:
		return bytesForms(k)
	case []byte:
		return append(bytesForms(k), string(k))
	}

	return nil
}

// bytesForms returns how fmt (%v, %x, %#v), slog's text handler (a quoted
// string) and encoding/json (base64) print the bytes of a key.
func bytesForms(b []byte) []string {
	return []string{
		fmt.Sprint(b)[1:30], fmt.Sprintf("%x", b)[:24], fmt.Sprintf("%#v", b)[8:36],
		strconv.Quote(string(b))[1:30], base64.StdEncoding.EncodeToString(b)[:24],
	}
}

// TestKeysRedactTheirMaterial: a private key — or an HMAC secret, carried
// as a PublicKey — printed with any fmt verb, logged through slog, or
// encoded with encoding/json, alone or inside a configuration, never
// reveals its material; every verb prints the redacted form.
func TestKeysRedactTheirMaterial(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	edKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xab}, ed25519.SeedSize))
	hmacKey := bytes.Repeat([]byte("hmac-secret-material/"), 2)

	cases := []struct {
		name   string
		key    any
		secret any
		want   string
	}{
		{"RSA private key", jwtsec.PrivateKey{KeyID: "rsa", Algorithm: jwtsec.RS256, Key: rsaKey}, rsaKey,
			`jwtsec.PrivateKey{KeyID: "rsa", Algorithm: RS256, Key: *rsa.PrivateKey REDACTED}`},
		{"ECDSA private key", jwtsec.PrivateKey{KeyID: "ec", Algorithm: jwtsec.ES256, Key: ecKey}, ecKey,
			`jwtsec.PrivateKey{KeyID: "ec", Algorithm: ES256, Key: *ecdsa.PrivateKey REDACTED}`},
		{"Ed25519 private key", jwtsec.PrivateKey{KeyID: "ed", Algorithm: jwtsec.EdDSA, Key: edKey}, edKey,
			`jwtsec.PrivateKey{KeyID: "ed", Algorithm: EdDSA, Key: ed25519.PrivateKey REDACTED}`},
		{"HMAC signing key", jwtsec.PrivateKey{KeyID: "hs", Algorithm: jwtsec.HS256, Key: hmacKey}, hmacKey,
			`jwtsec.PrivateKey{KeyID: "hs", Algorithm: HS256, Key: []uint8 REDACTED}`},
		{"HMAC verification key", jwtsec.PublicKey{KeyID: "hs", Algorithm: jwtsec.HS256, Key: hmacKey}, hmacKey,
			`jwtsec.PublicKey{KeyID: "hs", Algorithm: HS256, Key: []uint8 REDACTED}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			pointer := pointerTo(tc.key)

			for _, v := range []any{tc.key, pointer} {
				for way, rendered := range keyRenderings(t, v) {
					for _, material := range materialOf(tc.secret) {
						assert.NotContains(t, rendered, material, "%T rendered with %s", v, way)
					}
				}

				for _, verb := range keyVerbs {
					assert.Equal(t, tc.want, fmt.Sprintf(verb, v), "%T printed with %s", v, verb)
				}
			}
		})
	}
}

// pointerTo returns a pointer to a key value.
func pointerTo(key any) any {
	switch k := key.(type) {
	case jwtsec.PrivateKey:
		return &k
	case jwtsec.PublicKey:
		return &k
	}

	return nil
}

// TestAsymmetricPublicKeysStayReadable: a public key is no secret — its
// printed form names the key type, and encoding/json keeps encoding it as
// before.
func TestAsymmetricPublicKeysStayReadable(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pub := jwtsec.PublicKey{KeyID: "rsa", Algorithm: jwtsec.RS256, Key: &rsaKey.PublicKey}

	assert.Equal(t, `jwtsec.PublicKey{KeyID: "rsa", Algorithm: RS256, Key: *rsa.PublicKey}`, fmt.Sprintf("%+v", pub))

	raw, err := json.Marshal(pub)
	require.NoError(t, err)

	type plain jwtsec.PublicKey

	want, err := json.Marshal(plain(pub))
	require.NoError(t, err)
	assert.Equal(t, string(want), string(raw), "the default encoding")
	assert.Contains(t, string(raw), rsaKey.N.String(), "the modulus is public")
}

// TestSignersAndKeySetsRedactTheirKeys: the values that hold keys in
// unexported fields — a Signer, a static KeySet — print and log without
// the key material, which fmt would otherwise print field by field (it
// cannot call the methods of an unexported field's value).
func TestSignersAndKeySetsRedactTheirKeys(t *testing.T) {
	t.Parallel()

	edKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xcd}, ed25519.SeedSize))
	hmacKey := bytes.Repeat([]byte("hmac-secret-of-a-set/"), 2)
	edPriv := jwtsec.PrivateKey{KeyID: "ed", Algorithm: jwtsec.EdDSA, Key: edKey}
	hmacPriv := jwtsec.PrivateKey{KeyID: "hs", Algorithm: jwtsec.HS256, Key: hmacKey}
	publics := []jwtsec.PublicKey{
		{KeyID: "hs", Algorithm: jwtsec.HS256, Key: hmacKey},
		{KeyID: "ed", Algorithm: jwtsec.EdDSA, Key: edKey.Public()},
	}

	provider := jwtsec.NewStaticJWKS(publics, hmacPriv)

	set, err := provider.KeySet(context.Background())
	require.NoError(t, err)

	verifySet, err := jwtsec.NewStaticJWKS(publics).KeySet(context.Background())
	require.NoError(t, err)

	cases := []struct {
		name string
		v    any
		want string // what every verb prints
	}{
		{"Ed25519 signer", jwtsec.NewSigner(edPriv), `jwtsec.Signer{KeyID: "ed", Algorithm: EdDSA, Type: "JWT"}`},
		{"HMAC signer", jwtsec.NewSigner(hmacPriv, jwtsec.WithType(jwtsec.TypeAccessToken)),
			`jwtsec.Signer{KeyID: "hs", Algorithm: HS256, Type: "at+jwt"}`},
		{"static key set", set, `jwtsec.KeySet{KeyIDs: ["hs" "ed"], Active: "hs"}`},
		{"verification key set", verifySet, `jwtsec.KeySet{KeyIDs: ["hs" "ed"], Active: none}`},
		{"static provider", provider, `jwtsec.StaticJWKS{jwtsec.KeySet{KeyIDs: ["hs" "ed"], Active: "hs"}}`},
		{"RFC 9068 signer", jwtsec.NewOAuth2AccessTokenSigner(edPriv),
			`jwtsec.OAuth2AccessTokenSigner{jwtsec.Signer{KeyID: "ed", Algorithm: EdDSA, Type: "at+jwt"}}`},
		{"verifier", jwtsec.NewVerifier(provider, jwtsec.WithIssuer("https://op.example"), jwtsec.WithAudience("api")),
			`jwtsec.Verifier{Provider: jwtsec.staticProvider, Issuer: "https://op.example", Audience: ["api"], Type: ""}`},
		{"zero RFC 9068 signer", &jwtsec.OAuth2AccessTokenSigner{}, `jwtsec.OAuth2AccessTokenSigner{<nil>}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			for way, rendered := range keyRenderings(t, tc.v) {
				for _, material := range append(materialOf(edKey), materialOf(hmacKey)...) {
					assert.NotContains(t, rendered, material, "%T rendered with %s", tc.v, way)
				}
			}

			for _, verb := range keyVerbs {
				assert.Equal(t, tc.want, fmt.Sprintf(verb, tc.v), "%T printed with %s", tc.v, verb)
			}
		})
	}
}
