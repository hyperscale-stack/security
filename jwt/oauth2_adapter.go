// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec

import (
	"context"
	"fmt"

	"github.com/hyperscale-stack/security/oauth2/token"
)

// OAuth2AccessTokenSigner adapts a JWT [Signer] to the
// [oauth2/token.AccessTokenSigner] contract, producing RFC 9068
// ("JWT Profile for OAuth 2.0 Access Tokens") tokens.
//
// The adapter projects [token.AccessTokenClaims] onto a [StandardClaims]
// value: Issuer / Subject / Audience / Scope / IssuedAt / ExpiresAt map
// one-to-one; the OAuth2 ClientID is carried in the "client_id" claim
// (RFC 9068 §2.2.1) via a small payload type that embeds StandardClaims.
type OAuth2AccessTokenSigner struct {
	signer Signer
}

// NewOAuth2AccessTokenSigner wraps signer for OAuth2 use. The signer's
// algorithm and kid are reused as-is; callers needing per-token control
// can construct multiple signers and dispatch at the call site.
func NewOAuth2AccessTokenSigner(signer Signer) *OAuth2AccessTokenSigner {
	if signer == nil {
		panic("jwtsec.NewOAuth2AccessTokenSigner: nil Signer")
	}

	return &OAuth2AccessTokenSigner{signer: signer}
}

// SignAccessToken implements [oauth2/token.AccessTokenSigner].
func (s *OAuth2AccessTokenSigner) SignAccessToken(ctx context.Context, claims token.AccessTokenClaims) (string, error) {
	payload := oauth2AccessClaims{
		StandardClaims: StandardClaims{
			Issuer:    claims.Issuer,
			Subject:   claims.Subject,
			Audience:  Audience{claims.Audience},
			Scope:     claims.Scope,
			IssuedAt:  NewNumericDate(claims.IssuedAt),
			ExpiresAt: NewNumericDate(claims.ExpiresAt),
		},
		ClientID: claims.ClientID,
	}

	out, err := s.signer.Sign(ctx, payload)
	if err != nil {
		return "", fmt.Errorf("jwtsec: sign access token: %w", err)
	}

	return out, nil
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
