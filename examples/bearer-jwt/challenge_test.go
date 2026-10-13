// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	bareChallenge         = `Bearer realm="api"`
	invalidTokenChallenge = `Bearer realm="api", error="invalid_token", error_description="The access token is invalid or has expired."`
)

// foreignToken is a well-formed token for the example's issuer and audience,
// signed by a key the example does not trust.
func foreignToken(t *testing.T) string {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	now := time.Now()

	signer, err := jwtsec.NewSigner(jwtsec.PrivateKey{KeyID: keyID, Algorithm: jwtsec.EdDSA, Key: priv},
		jwtsec.WithType(jwtsec.TypeAccessToken))
	require.NoError(t, err)

	token, err := signer.Sign(context.Background(), &jwtsec.StandardClaims{
		Issuer:    issuer,
		Subject:   "mallory",
		Audience:  jwtsec.Audience{audience},
		IssuedAt:  jwtsec.NewNumericDate(now),
		ExpiresAt: jwtsec.NewNumericDate(now.Add(time.Hour)),
		Scope:     "resource:read",
	})
	require.NoError(t, err)

	return token
}

// Audit CORE-10 (probe TestZZAuditBearerChallengeErrorCodes): a bad signature
// or a malformed token got a bare "Bearer" challenge. RFC 6750 §3: the
// challenge carries a realm; RFC 9068 §4: every failed check of a JWT
// access token carries error="invalid_token"; §3.1: a valid token without
// the scope gets error="insufficient_scope".
func TestBearerJWTChallenges(t *testing.T) {
	t.Parallel()

	handler, mint, err := newServer()
	require.NoError(t, err)

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	valid, err := mint("resource:read", time.Now())
	require.NoError(t, err)

	expired, err := mint("resource:read", time.Now().Add(-time.Hour))
	require.NoError(t, err)

	wrongScope, err := mint("other:read", time.Now())
	require.NoError(t, err)

	cases := []struct {
		name          string
		authorization []string
		status        int
		challenge     []string
	}{
		{"no token", nil, http.StatusUnauthorized, []string{bareChallenge}},
		{"malformed token", []string{"Bearer not-a-jwt"}, http.StatusUnauthorized, []string{invalidTokenChallenge}},
		{"untrusted signature", []string{"Bearer " + foreignToken(t)}, http.StatusUnauthorized, []string{invalidTokenChallenge}},
		{"expired token", []string{"Bearer " + expired}, http.StatusUnauthorized, []string{invalidTokenChallenge}},
		{"valid token without the scope", []string{"Bearer " + wrongScope}, http.StatusForbidden,
			[]string{`Bearer realm="api", error="insufficient_scope", error_description="The request requires higher privileges than provided by the access token."`}},
		{"repeated Authorization", []string{"Bearer " + valid, "Bearer not-a-jwt"}, http.StatusBadRequest,
			[]string{`Bearer realm="api", error="invalid_request", error_description="The request is malformed."`}},
		{"valid token", []string{"Bearer " + valid}, http.StatusOK, nil},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			req, err := http.NewRequest(http.MethodGet, srv.URL+"/reports", nil)
			require.NoError(t, err)

			for _, v := range c.authorization {
				req.Header.Add("Authorization", v)
			}

			r, err := srv.Client().Do(req)
			require.NoError(t, err)
			t.Cleanup(func() { _ = r.Body.Close() })

			assert.Equal(t, c.status, r.StatusCode)
			assert.Equal(t, c.challenge, r.Header.Values("WWW-Authenticate"))
		})
	}
}
