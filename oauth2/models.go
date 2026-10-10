// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import "time"

// AuthorizationCode is the record persisted between the /authorize call and
// the matching /token call. The Code field carries the raw, single-use value
// returned to the user-agent; storage implementations key the record by
// CodeHash, never persist the raw value, consume it atomically, and keep
// the consumed record until ExpiresAt so that a replay is recognized (RFC
// 6749 §4.1.2 + OAuth 2.0 BCP §4.5; see [AuthorizationCodeStore]).
type AuthorizationCode struct {
	// Code is the raw, single-use authorization code as issued to the
	// user-agent. Storage implementations persist its hash, never the raw
	// value. The struct carries the raw form because the issuance flow
	// needs to redirect it.
	Code string
	// CodeHash is the storage key: HashToken(nil, Code), set by the issuer
	// (the authorization endpoint). Stores reject an empty one.
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
	// FamilyID identifies the refresh-token family the token belongs to,
	// so revoking the family revokes it too. Empty for tokens issued
	// outside a family (client_credentials, the implicit flow). At most
	// [MaxFamilyIDLength] bytes.
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
	// entire family (RFC 9700 §4.14.2). Never empty for a stored refresh
	// token; at most [MaxFamilyIDLength] bytes.
	FamilyID string
	// Consumed reports that the token can no longer be exchanged: it was
	// rotated, or its family was revoked. Presenting a consumed token is
	// reuse, which MUST trigger family revocation. Lookups set it; a new
	// token is never persisted consumed.
	Consumed bool
}

// IsExpired reports whether the token has passed its expiry.
func (t *RefreshToken) IsExpired(now time.Time) bool {
	return now.After(t.ExpiresAt)
}

// TokenPair couples an access token with the refresh token issued alongside
// it. Refresh is nil when the grant issues none: client_credentials, a grant
// without a RefreshTokens generator, or a non-rotating refresh under
// Profile20. It is the unit of persistence — [Storage] writes a pair
// atomically, through SaveTokenPair or RotateRefreshToken — and what the
// grant handlers return; the response writer turns it into the RFC 6749
// §5.1 JSON body.
type TokenPair struct {
	Access  AccessToken
	Refresh *RefreshToken
}

// Validate reports, as an invalid_request [*Error], a pair no [Storage]
// may persist: a nil pair, an access token without hash or with a family
// ID longer than [MaxFamilyIDLength], or a refresh token without hash,
// outside a family, in another family than the access token, or already
// consumed. A refresh token only ever travels with an access token of its
// own family.
func (p *TokenPair) Validate() error {
	switch {
	case p == nil:
		return ErrInvalidRequest.WithDescription("storage: nil token pair")
	case p.Access.TokenHash == "":
		return ErrInvalidRequest.WithDescription("storage: empty access token hash")
	case len(p.Access.FamilyID) > MaxFamilyIDLength:
		return ErrInvalidRequest.WithDescription("storage: token family id too long")
	case p.Refresh == nil:
		return nil
	case p.Refresh.TokenHash == "":
		return ErrInvalidRequest.WithDescription("storage: empty refresh token hash")
	case p.Refresh.FamilyID == "":
		return ErrInvalidRequest.WithDescription("storage: refresh token outside a token family")
	case p.Refresh.FamilyID != p.Access.FamilyID:
		return ErrInvalidRequest.WithDescription("storage: refresh and access tokens in different families")
	case p.Refresh.Consumed:
		return ErrInvalidRequest.WithDescription("storage: refresh token already consumed")
	default:
		return nil
	}
}
