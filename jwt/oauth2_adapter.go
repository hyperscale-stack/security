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
// IssuedAt / ExpiresAt / ClientID map one-to-one — ClientID to the
// "client_id" claim (RFC 9068 §2.2). A client_credentials token's Subject
// is its ClientID (RFC 9068 §2.2): resource servers tell it from a
// resource owner's token with [AccessTokenPrincipal.SubjectIsClient].
type OAuth2AccessTokenSigner struct {
	signer Signer
}

// NewOAuth2AccessTokenSigner returns the RFC 9068 access-token signer of
// key: it builds its own [Signer], typed [TypeAccessToken], so no access
// token it signs can go out untyped. Like [NewSigner], it fails with
// [ErrInvalidKey] on a key that cannot sign with its Algorithm. Publish
// the key's public half where resource servers fetch the authorization
// server's keys (RFC 9068 §4: its jwks_uri).
func NewOAuth2AccessTokenSigner(key PrivateKey) (*OAuth2AccessTokenSigner, error) {
	s, err := NewSigner(key, WithType(TypeAccessToken))
	if err != nil {
		return nil, err
	}

	return &OAuth2AccessTokenSigner{signer: s}, nil
}

// SignAccessToken implements [oauth2/token.AccessTokenSigner]. It refuses,
// with [ErrUnsignableClaims] and without signing anything, claims lacking
// a value RFC 9068 §2.2 makes REQUIRED — an empty Issuer, Subject,
// Audience or ClientID, a zero IssuedAt or ExpiresAt — or whose ExpiresAt
// is not after IssuedAt (jti is always generated). An [oauth2.IssuerResolver]
// returning an empty audience therefore makes JWT access-token issuance
// fail: give every realm its resource-server audience.
func (s *OAuth2AccessTokenSigner) SignAccessToken(ctx context.Context, claims token.AccessTokenClaims) (string, error) {
	if err := checkAccessTokenClaims(claims); err != nil {
		return "", err
	}

	jti, err := newJTI()
	if err != nil {
		return "", err
	}

	payload := StandardClaims{
		Issuer:    claims.Issuer,
		Subject:   claims.Subject,
		Audience:  Audience{claims.Audience},
		Scope:     claims.Scope,
		ClientID:  claims.ClientID,
		IssuedAt:  NewNumericDate(claims.IssuedAt),
		ExpiresAt: NewNumericDate(claims.ExpiresAt),
		JWTID:     jti,
	}

	out, err := s.signer.Sign(ctx, payload)
	if err != nil {
		return "", fmt.Errorf("jwtsec: sign access token: %w", err)
	}

	return out, nil
}

// checkAccessTokenClaims refuses claims lacking an RFC 9068 §2.2 REQUIRED
// value, or expiring at or before their issuance.
func checkAccessTokenClaims(c token.AccessTokenClaims) error {
	missing := ""

	switch {
	case c.Issuer == "":
		missing = claimIss
	case c.Subject == "":
		missing = claimSub
	case c.Audience == "":
		missing = claimAud
	case c.ClientID == "":
		missing = claimClientID
	case c.IssuedAt.IsZero():
		missing = claimIat
	case c.ExpiresAt.IsZero():
		missing = claimExp
	}

	if missing != "" {
		return fmt.Errorf("%w: RFC 9068 requires %s", ErrUnsignableClaims, missing)
	}

	if !c.ExpiresAt.After(c.IssuedAt) {
		return fmt.Errorf("%w: exp is not after iat", ErrUnsignableClaims)
	}

	return nil
}

// newJTI returns a fresh 128-bit, base64url-encoded JWT ID.
func newJTI() (string, error) {
	b := make([]byte, jtiBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("jwtsec: read random jti: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Compile-time interface check (defensive; the import path makes the
// dependency explicit).
var _ token.AccessTokenSigner = (*OAuth2AccessTokenSigner)(nil)
