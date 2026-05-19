// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import "time"

// AuthorizationCode is the record persisted between the /authorize call and
// the matching /token call. The Code field carries the raw, single-use value
// returned to the user-agent; storage implementations MUST hash it before
// persisting and consume atomically (RFC 6749 §4.1.2 + OAuth 2.0 BCP §4.5).
type AuthorizationCode struct {
	// Code is the raw, single-use authorization code as issued to the
	// user-agent. Storage implementations persist its hash, never the raw
	// value. The struct carries the raw form because the issuance flow
	// needs to redirect it.
	Code string
	// CodeHash is the storage-side hash of Code. Filled in by the storage
	// layer; the issuance flow leaves it empty.
	CodeHash string
	// ClientID is the requesting client's identifier.
	ClientID string
	// Subject is the resource-owner subject (`sub` claim equivalent).
	Subject string
	// RedirectURI is the redirect_uri sent to /authorize; the matching
	// /token call MUST present the same URI.
	RedirectURI string
	// Scope is the granted (post-consent) scope.
	Scope string
	// CodeChallenge is the PKCE challenge (RFC 7636 §4.2). Required for
	// public clients; required for every client under OAuth 2.0 BCP §2.1.1.
	CodeChallenge string
	// CodeChallengeMethod is the PKCE method ("S256" or "plain").
	CodeChallengeMethod string
	// Nonce echoes the OIDC nonce parameter for replay protection in id
	// tokens. Empty for plain OAuth2 flows.
	Nonce string
	// IssuedAt is the wall-clock issuance time.
	IssuedAt time.Time
	// ExpiresAt is the wall-clock expiry time. Codes typically live 10
	// minutes (RFC 6749 §4.1.2).
	ExpiresAt time.Time
}

// IsExpired reports whether the code has passed its expiry.
func (c *AuthorizationCode) IsExpired(now time.Time) bool {
	return now.After(c.ExpiresAt)
}

// AccessToken is the record persisted for an issued access token. The Token
// field carries the raw value returned to the client; the TokenHash field
// is the storage key. JWT-formatted tokens still have a TokenHash so that
// revocation and introspection can be implemented uniformly.
type AccessToken struct {
	Token     string
	TokenHash string
	ClientID  string
	Subject   string
	Scope     string
	IssuedAt  time.Time
	ExpiresAt time.Time
	// FamilyID identifies the token family this access token belongs to,
	// used for refresh-token rotation and reuse detection. Empty when
	// rotation is disabled.
	FamilyID string
	// Audience is the configured aud claim (typically the resource server
	// identifier). Single-valued in this model; servers needing multi-aud
	// should rebuild the model in their JWT signer.
	Audience string
}

// IsExpired reports whether the token has passed its expiry.
func (t *AccessToken) IsExpired(now time.Time) bool {
	return now.After(t.ExpiresAt)
}

// RefreshToken is the record persisted for a refresh token. Refresh tokens
// are ALWAYS opaque and ALWAYS stored hashed (never the raw value).
type RefreshToken struct {
	Token     string // raw value, only present transiently during issuance
	TokenHash string
	ClientID  string
	Subject   string
	Scope     string
	IssuedAt  time.Time
	ExpiresAt time.Time
	// FamilyID groups every refresh token derived from the same original
	// authorisation. Rotation issues a new RefreshToken with the same
	// FamilyID; reuse of a consumed token leads to revocation of the
	// entire family (OAuth 2.0 BCP §8.10.3).
	FamilyID string
	// Consumed indicates whether the token has been rotated. Reuse of a
	// consumed token MUST trigger family revocation.
	Consumed bool
}

// IsExpired reports whether the token has passed its expiry.
func (t *RefreshToken) IsExpired(now time.Time) bool {
	return now.After(t.ExpiresAt)
}

// TokenPair couples an access token with its companion refresh token (when
// rotation is enabled). The grant handlers return this; the response writer
// turns it into the RFC 6749 §5.1 JSON body.
type TokenPair struct {
	Access  AccessToken
	Refresh *RefreshToken
}
