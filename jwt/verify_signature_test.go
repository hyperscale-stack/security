// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifySignatureReturnsTheVerifiedToken(t *testing.T) {
	t.Parallel()

	priv, pub := genECDSA(t)

	// Expired long ago: VerifySignature checks no claim, exp included.
	claims := jwtsec.StandardClaims{Subject: "alice", ExpiresAt: jwtsec.NewNumericDate(time.Unix(1000, 0))}
	jws, err := jwtsec.NewSigner(priv).Sign(context.Background(), claims)
	require.NoError(t, err)

	got, err := jwtsec.VerifySignature(context.Background(), jws, []jwtsec.PublicKey{pub})
	require.NoError(t, err)
	assert.Equal(t, jwtsec.ES256, got.Algorithm)
	assert.Equal(t, "ec-1", got.KeyID)
	assert.Equal(t, jwtsec.TypeJWT, got.Type)

	var decoded jwtsec.StandardClaims
	require.NoError(t, json.Unmarshal(got.Payload, &decoded))
	assert.Equal(t, "alice", decoded.Subject)

	untyped, err := jwtsec.VerifySignature(context.Background(), signWithHeader(t, priv, "", claims), []jwtsec.PublicKey{pub})
	require.NoError(t, err)
	assert.Empty(t, untyped.Type, "an absent typ reads empty")
}

func TestVerifySignatureSelectsTheKeyByKid(t *testing.T) {
	t.Parallel()

	priv1, pub1 := genECDSA(t)
	priv2, pub2 := genECDSA(t)
	priv2.KeyID, pub2.KeyID = "ec-2", "ec-2"

	keys := []jwtsec.PublicKey{pub1, pub2}

	for _, priv := range []jwtsec.PrivateKey{priv1, priv2} {
		jws, err := jwtsec.NewSigner(priv).Sign(context.Background(), validClaims())
		require.NoError(t, err)

		got, err := jwtsec.VerifySignature(context.Background(), jws, keys)
		require.NoError(t, err)
		assert.Equal(t, priv.KeyID, got.KeyID)
	}
}

func TestVerifySignatureRefusals(t *testing.T) {
	t.Parallel()

	ecPriv, ecPub := genECDSA(t)
	rsaPriv, rsaPub := genRSA(t)
	other, _ := genECDSA(t) // same kid "ec-1", another key

	signed := func(priv jwtsec.PrivateKey) string {
		jws, err := jwtsec.NewSigner(priv).Sign(context.Background(), validClaims())
		require.NoError(t, err)

		return jws
	}

	noKid := ecPriv
	noKid.KeyID = ""

	ps256 := rsaPriv
	ps256.Algorithm = jwtsec.PS256

	pubNoAlg := ecPub
	pubNoAlg.Algorithm = ""

	cases := []struct {
		name    string
		token   string
		keys    []jwtsec.PublicKey
		allowed []jwtsec.Algorithm
		want    error
	}{
		{"signature by another key", signed(other), []jwtsec.PublicKey{ecPub}, nil, jwtsec.ErrInvalidSignature},
		{"unknown kid", signed(ecPriv), []jwtsec.PublicKey{rsaPub}, nil, jwtsec.ErrInvalidSignature},
		{"no kid among several keys", signed(noKid), []jwtsec.PublicKey{ecPub, rsaPub}, nil, jwtsec.ErrInvalidSignature},
		{"key bound to another algorithm", signed(ps256), []jwtsec.PublicKey{rsaPub}, nil, jwtsec.ErrInvalidSignature},
		{"key without algorithm", signed(ecPriv), []jwtsec.PublicKey{pubNoAlg}, nil, jwtsec.ErrInvalidSignature},
		{"algorithm not allowed", signed(rsaPriv), []jwtsec.PublicKey{rsaPub}, []jwtsec.Algorithm{jwtsec.ES256}, jwtsec.ErrAlgorithmNotAllowed},
		{"alg none", unsignedToken(t), []jwtsec.PublicKey{ecPub}, nil, jwtsec.ErrAlgorithmNotAllowed},
		{"HS256 forged with the RSA public key", hmacWithRSAPublicKey(t, rsaPub), []jwtsec.PublicKey{rsaPub}, nil, jwtsec.ErrAlgorithmNotAllowed},
		{"tampered payload", tamper(signed(ecPriv)), []jwtsec.PublicKey{ecPub}, nil, jwtsec.ErrInvalidSignature},
		{"JSON serialization", jsonSerialization(t, ecPriv), []jwtsec.PublicKey{ecPub}, nil, jwtsec.ErrMalformedToken},
		{"garbage", "not.a.jws", []jwtsec.PublicKey{ecPub}, nil, jwtsec.ErrMalformedToken},
		{"empty", "", []jwtsec.PublicKey{ecPub}, nil, jwtsec.ErrMalformedToken},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := jwtsec.VerifySignature(context.Background(), tc.token, tc.keys, tc.allowed...)
			require.ErrorIs(t, err, tc.want)
			assert.Nil(t, got)
		})
	}
}

func TestVerifySignatureAcceptsANoKidTokenWithOneKey(t *testing.T) {
	t.Parallel()

	priv, pub := genECDSA(t)
	priv.KeyID = ""

	jws, err := jwtsec.NewSigner(priv).Sign(context.Background(), validClaims())
	require.NoError(t, err)

	got, err := jwtsec.VerifySignature(context.Background(), jws, []jwtsec.PublicKey{pub})
	require.NoError(t, err)
	assert.Empty(t, got.KeyID)
}

// unsignedToken is an "alg":"none" JWT.
func unsignedToken(t *testing.T) string {
	t.Helper()

	enc := base64.RawURLEncoding
	payload, err := json.Marshal(validClaims())
	require.NoError(t, err)

	return enc.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + enc.EncodeToString(payload) + "."
}

// hmacWithRSAPublicKey forges an HS256 token keyed with the DER bytes of an
// RSA public key: the classic algorithm-confusion attack.
func hmacWithRSAPublicKey(t *testing.T, pub jwtsec.PublicKey) string {
	t.Helper()

	der, err := x509.MarshalPKIXPublicKey(pub.Key)
	require.NoError(t, err)

	enc := base64.RawURLEncoding
	payload, err := json.Marshal(validClaims())
	require.NoError(t, err)

	signing := enc.EncodeToString([]byte(`{"alg":"HS256","kid":"rsa-1","typ":"JWT"}`)) + "." + enc.EncodeToString(payload)
	mac := hmac.New(sha256.New, der)
	mac.Write([]byte(signing))

	return signing + "." + enc.EncodeToString(mac.Sum(nil))
}

// tamper swaps the payload of a compact JWS for another one.
func tamper(jws string) string {
	parts := strings.Split(jws, ".")
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"mallory"}`))

	return strings.Join(parts, ".")
}

// jsonSerialization signs with the general JWS JSON serialization.
func jsonSerialization(t *testing.T, priv jwtsec.PrivateKey) string {
	t.Helper()

	s, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(priv.Algorithm),
		Key:       jose.JSONWebKey{Key: priv.Key, KeyID: priv.KeyID},
	}, nil)
	require.NoError(t, err)

	obj, err := s.Sign([]byte(`{"sub":"alice"}`))
	require.NoError(t, err)

	return obj.FullSerialize()
}
