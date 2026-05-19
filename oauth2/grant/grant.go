// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package grant ships the grant-type handlers consumed by the OAuth2
// server's /token endpoint. Each handler satisfies [oauth2.Grant] and is
// registered in the server's grant table at construction time.
//
// Three grants are shipped:
//
//   - authorization_code (with PKCE; PKCE is mandatory in
//     [oauth2.Profile20BCP] and [oauth2.Profile21Draft])
//   - client_credentials
//   - refresh_token (with rotation + reuse detection)
//
// Legacy grants (password, implicit) live behind explicit opt-in helpers
// and are refused outside [oauth2.Profile20].
package grant

import (
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/token"
)

// Config gathers the runtime knobs every grant needs.
type Config struct {
	// Storage is the persistence layer.
	Storage oauth2.Storage
	// AccessTokens issues access tokens (opaque or JWT).
	AccessTokens token.AccessTokenGenerator
	// RefreshTokens issues refresh tokens. Optional — when nil, the
	// grant emits no refresh token.
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

// Request and Response are type aliases anchoring the contract in the
// parent oauth2 package so handlers and the Server share one definition.
type (
	Request  = oauth2.GrantRequest
	Response = oauth2.GrantResponse
)
