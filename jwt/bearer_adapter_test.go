// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec_test

import (
	"context"
	"testing"
	"time"

	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBearerVerifierDefaultResolverExposesScopesAsAuthorities(t *testing.T) {
	t.Parallel()

	priv, pub := genECDSA(t)
	signer := jwtsec.NewSigner(priv)
	verifier := jwtsec.NewVerifier(jwtsec.NewStaticJWKS([]jwtsec.PublicKey{pub}))

	token, _ := signer.Sign(context.Background(), &jwtsec.StandardClaims{
		Subject:   "alice",
		Scope:     "read:mail write:mail admin",
		ExpiresAt: jwtsec.NewNumericDate(time.Now().Add(time.Hour)),
	})

	tv := jwtsec.BearerVerifier(verifier, nil)
	got, err := tv.Verify(context.Background(), token)
	require.NoError(t, err)
	assert.True(t, got.IsAuthenticated())
	assert.Equal(t, "alice", got.Principal().Subject())
	assert.ElementsMatch(t,
		[]string{"scope:read:mail", "scope:write:mail", "scope:admin"},
		got.Authorities(),
	)
}

func TestBearerVerifierCustomResolver(t *testing.T) {
	t.Parallel()

	priv, pub := genECDSA(t)
	signer := jwtsec.NewSigner(priv)
	verifier := jwtsec.NewVerifier(jwtsec.NewStaticJWKS([]jwtsec.PublicKey{pub}))

	token, _ := signer.Sign(context.Background(), &jwtsec.StandardClaims{
		Subject:   "alice",
		ExpiresAt: jwtsec.NewNumericDate(time.Now().Add(time.Hour)),
	})

	tv := jwtsec.BearerVerifier(verifier, func(c *jwtsec.StandardClaims) []string {
		return []string{"ROLE_" + c.Subject}
	})

	got, err := tv.Verify(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, []string{"ROLE_alice"}, got.Authorities())
}

func TestBearerVerifierPropagatesVerifierError(t *testing.T) {
	t.Parallel()

	priv, _ := genECDSA(t)
	signer := jwtsec.NewSigner(priv)
	// Verifier with no keys -> ErrInvalidSignature.
	verifier := jwtsec.NewVerifier(jwtsec.NewStaticJWKS(nil))

	token, _ := signer.Sign(context.Background(), &jwtsec.StandardClaims{Subject: "alice"})

	tv := jwtsec.BearerVerifier(verifier, nil)
	_, err := tv.Verify(context.Background(), token)
	assert.ErrorIs(t, err, jwtsec.ErrInvalidSignature)
}
