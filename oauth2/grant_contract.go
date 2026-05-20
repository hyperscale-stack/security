// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"context"
	"net/url"
	"time"
)

// GrantRequest is the parsed /token request handed to a [Grant]. The
// server unpacks the HTTP request once and feeds this struct to whichever
// Grant matches the grant_type parameter.
type GrantRequest struct {
	Client   Client
	Form     url.Values
	Issuer   string
	Audience string
	Now      time.Time
	// Profile is the server's active security profile. Grants use it to
	// enforce the profile-mandated rules at runtime (e.g. PKCE required,
	// "plain" PKCE refused). A profile can only tighten a grant's own
	// configuration, never loosen it.
	Profile Profile
}

// GrantResponse is what a grant hands back to the server. The HTTP layer
// projects it onto the RFC 6749 §5.1 JSON body.
type GrantResponse struct {
	Pair        TokenPair
	Scope       string
	TokenType   string // typically "Bearer"
	ExtraParams map[string]any
}

// Grant validates and processes one OAuth2 grant_type value. Each Grant is
// invoked exclusively by the server's /token endpoint; the server
// authenticates the client beforehand.
type Grant interface {
	// Type returns the grant_type identifier.
	Type() string
	// Handle runs the grant. Returns oauth2.* sentinel errors that the
	// server then projects onto the OAuth2 JSON error envelope.
	Handle(ctx context.Context, req GrantRequest) (*GrantResponse, error)
}
