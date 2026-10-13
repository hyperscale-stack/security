// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPublicKeyRedactsNonPublicMaterial pins that a PublicKey prints, logs
// and JSON-encodes key material only for a public asymmetric key: an HMAC
// secret held as a jose.JSONWebKey (a form go-jose verifies with), and a
// private key carried in a PublicKey by mistake, are redacted (audit
// CORE-15: json.Marshal leaked both).
func TestPublicKeyRedactsNonPublicMaterial(t *testing.T) {
	t.Parallel()

	secret := bytes.Repeat([]byte("hmac-secret-material/"), 2)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	url := base64.RawURLEncoding

	cases := []struct {
		name     string
		key      any
		material []string
	}{
		{"HMAC secret in a JWK value", jose.JSONWebKey{Key: secret}, append(materialOf(secret), url.EncodeToString(secret)[:24])},
		{"HMAC secret in a JWK pointer", &jose.JSONWebKey{Key: secret}, append(materialOf(secret), url.EncodeToString(secret)[:24])},
		{"private RSA key", rsaKey, materialOf(rsaKey)},
		{"private RSA key in a JWK", jose.JSONWebKey{Key: rsaKey}, append(materialOf(rsaKey), url.EncodeToString(rsaKey.D.Bytes())[:24])},
		{"private EC key", ecKey, materialOf(ecKey)},
		{"private Ed25519 key", edKey, materialOf(edKey)},
		{"unknown type", struct{ Secret string }{"opaque-s3cr3t-value"}, []string{"opaque-s3cr3t-value"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			pk := jwtsec.PublicKey{KeyID: "k", Algorithm: jwtsec.RS256, Key: tc.key}

			for way, rendered := range keyRenderings(t, pk) {
				for _, m := range tc.material {
					assert.NotContains(t, rendered, m, "%s leaks %T", way, tc.key)
				}
			}

			raw, err := json.Marshal(pk)
			require.NoError(t, err)
			assert.Contains(t, string(raw), "REDACTED")
			assert.Contains(t, pk.String(), "REDACTED")
		})
	}

	// A public asymmetric key keeps its public fields.
	raw, err := json.Marshal(jwtsec.PublicKey{KeyID: "k", Algorithm: jwtsec.RS256, Key: &rsaKey.PublicKey})
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "REDACTED")
	assert.Contains(t, string(raw), rsaKey.N.String())
}
