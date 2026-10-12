// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/hyperscale-stack/security/oauth2/token"
)

// jtiBytes is the size of the random jti of an access token: 128 bits, so
// identifiers never collide (RFC 9068 §2.2, RFC 7519 §4.1.7).
const jtiBytes = 16

// OAuth2AccessTokenSigner adapts a JWT [Signer] to the
// [oauth2/token.AccessTokenSigner] contract, producing RFC 9068
// ("JWT Profile for OAuth 2.0 Access Tokens") tokens.
//
// Every token is explicitly typed "at+jwt" (RFC 9068 §2.1) — so a resource
// server verifying with [WithType]([TypeAccessToken]) refuses an OpenID
// Connect ID Token signed by the same key — and carries a fresh random
// "jti" (RFC 9068 §2.2). The adapter projects [token.AccessTokenClaims]
// onto a [StandardClaims] value: Issuer / Subject / Audience / Scope /
// IssuedAt / ExpiresAt map one-to-one; the OAuth2 ClientID is carried in
// the "client_id" claim (RFC 9068 §2.2) via a small payload type that
// embeds StandardClaims.
type OAuth2AccessTokenSigner struct {
	signer Signer
}

// NewOAuth2AccessTokenSigner returns the RFC 9068 access-token signer of
// key: it builds its own [Signer], typed [TypeAccessToken], so no access
// token it signs can go out untyped. Like [NewSigner], it panics on a key
// without Algorithm or Key. Publish the key's public half where resource
// servers fetch the authorization server's keys (RFC 9068 §4: its jwks_uri).
func NewOAuth2AccessTokenSigner(key PrivateKey) *OAuth2AccessTokenSigner {
	return &OAuth2AccessTokenSigner{signer: NewSigner(key, WithType(TypeAccessToken))}
}

// SignAccessToken implements [oauth2/token.AccessTokenSigner].
func (s *OAuth2AccessTokenSigner) SignAccessToken(ctx context.Context, claims token.AccessTokenClaims) (string, error) {
	jti, err := newJTI()
	if err != nil {
		return "", err
	}

	payload := oauth2AccessClaims{
		StandardClaims: StandardClaims{
			Issuer:    claims.Issuer,
			Subject:   claims.Subject,
			Audience:  Audience{claims.Audience},
			Scope:     claims.Scope,
			IssuedAt:  NewNumericDate(claims.IssuedAt),
			ExpiresAt: NewNumericDate(claims.ExpiresAt),
			JWTID:     jti,
		},
		ClientID: claims.ClientID,
	}

	out, err := s.signer.Sign(ctx, payload)
	if err != nil {
		return "", fmt.Errorf("jwtsec: sign access token: %w", err)
	}

	return out, nil
}

// newJTI returns a fresh 128-bit, base64url-encoded JWT ID.
func newJTI() (string, error) {
	b := make([]byte, jtiBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("jwtsec: read random jti: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

// oauth2AccessClaims is the on-wire payload of an RFC 9068 access token.
// "client_id" is the only extension over the standard claim set.
type oauth2AccessClaims struct {
	StandardClaims

	ClientID string `json:"client_id,omitempty"`
}

// Compile-time interface check (defensive; the import path makes the
// dependency explicit).
var _ token.AccessTokenSigner = (*OAuth2AccessTokenSigner)(nil)
