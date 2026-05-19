// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package grant ships the grant-type handlers consumed by the OAuth2
// server's /token endpoint. Each grant satisfies the [Grant] contract and
// is registered in the server's grant table at construction time.
//
// Three grants are shipped:
//
//   - authorization_code (with PKCE; PKCE is mandatory in
//     [Profile20BCP] and [Profile21Draft])
//   - client_credentials
//   - refresh_token (with rotation + reuse detection)
//
// Legacy grants (password, implicit) live behind explicit opt-in helpers
// and are refused outside [Profile20].
package grant

import (
	"context"
	"net/url"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/token"
)

// Request is the parsed /token request handed to a [Grant]. The OAuth2
// server unpacks the HTTP request once and feeds this struct to whichever
// Grant matches the grant_type parameter.
type Request struct {
	// Client is the authenticated client (already verified by the
	// configured clientauth.ClientAuthenticator before the grant runs).
	Client oauth2.Client
	// Form carries the rest of the request parameters (code, redirect_uri,
	// code_verifier, refresh_token, scope, …).
	Form url.Values
	// Issuer is the resolved issuer string for this request (set by the
	// server's IssuerResolver). Grants pass it to the access-token
	// generator so JWTs carry the right iss claim.
	Issuer string
	// Audience is the resource server identifier(s) the grant SHOULD set
	// on issued tokens. Single-valued in this model.
	Audience string
	// Now is the current wall-clock time captured by the server at the
	// start of the request; grants use it instead of time.Now() so tests
	// remain deterministic.
	Now time.Time
}

// Response is what the grant hands back to the server. The HTTP layer
// projects it onto the RFC 6749 §5.1 JSON body.
type Response struct {
	Pair        oauth2.TokenPair
	Scope       string
	TokenType   string // typically "Bearer"
	ExtraParams map[string]any
}

// Grant validates and processes one OAuth2 grant_type value. Each Grant is
// invoked exclusively by the server's /token endpoint; the server is
// responsible for authenticating the client beforehand.
type Grant interface {
	// Type returns the grant_type identifier ("authorization_code",
	// "client_credentials", "refresh_token").
	Type() string

	// Handle runs the grant. Returns oauth2.* sentinel errors that the
	// server then projects onto the OAuth2 JSON error envelope.
	Handle(ctx context.Context, req Request) (*Response, error)
}

// Config gathers the runtime knobs every grant needs. Embedding this in a
// constructor keeps the package free of a hard dependency on the Server
// (which lives in the parent oauth2 package).
type Config struct {
	// Storage is the persistence layer.
	Storage oauth2.Storage
	// AccessTokens issues access tokens (opaque or JWT, decided by the
	// server composition root).
	AccessTokens token.AccessTokenGenerator
	// RefreshTokens issues refresh tokens. Optional — when nil, the grant
	// emits no refresh token.
	RefreshTokens token.RefreshTokenGenerator
	// AccessTTL is the access-token expiry window.
	AccessTTL time.Duration
	// RefreshTTL is the refresh-token expiry window. Honored when
	// RefreshTokens is non-nil.
	RefreshTTL time.Duration
	// RequirePKCE forces PKCE on authorization_code; default in BCP/21
	// profiles. The authorization_code grant honors this independently
	// of public-vs-confidential client type.
	RequirePKCE bool
	// RotateRefreshTokens emits a fresh refresh token on every
	// /token?grant_type=refresh_token call and marks the old one
	// consumed; reuse triggers family revocation. Default true in BCP/21.
	RotateRefreshTokens bool
}
