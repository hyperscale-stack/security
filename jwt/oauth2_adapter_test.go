// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec_test

import (
	"context"
	"strings"
	"testing"
	"time"

	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/hyperscale-stack/security/oauth2/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOAuth2AccessTokenSignerProducesRFC9068Token(t *testing.T) {
	t.Parallel()

	priv, pub := genECDSA(t)
	signer := jwtsec.NewSigner(priv)
	adapter := jwtsec.NewOAuth2AccessTokenSigner(signer)

	issued := time.Now().Truncate(time.Second)
	expires := issued.Add(time.Hour)

	jws, err := adapter.SignAccessToken(context.Background(), token.AccessTokenClaims{
		Issuer:    "https://auth.example",
		Subject:   "alice",
		Audience:  "api",
		ClientID:  "my-client",
		Scope:     "read:mail",
		IssuedAt:  issued,
		ExpiresAt: expires,
	})
	require.NoError(t, err)
	assert.Equal(t, 2, strings.Count(jws, "."), "compact JWS has 3 segments")

	// Verify the token round-trips through the verifier.
	verifier := jwtsec.NewVerifier(
		jwtsec.NewStaticJWKS([]jwtsec.PublicKey{pub}),
		jwtsec.WithIssuer("https://auth.example"),
		jwtsec.WithAudience("api"),
	)

	var got struct {
		jwtsec.StandardClaims
		ClientID string `json:"client_id"`
	}

	_, err = verifier.Verify(context.Background(), jws, &got)
	require.NoError(t, err)
	assert.Equal(t, "alice", got.Subject)
	assert.Equal(t, "my-client", got.ClientID)
	assert.Equal(t, "read:mail", got.Scope)
}

func TestNewOAuth2AccessTokenSignerPanicsOnNilSigner(t *testing.T) {
	t.Parallel()

	assert.Panics(t, func() { jwtsec.NewOAuth2AccessTokenSigner(nil) })
}
