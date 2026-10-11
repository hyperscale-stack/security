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
	// "plain" PKCE refused, refresh-token rotation forced). A profile can
	// only tighten a grant's own configuration, never loosen it.
	Profile Profile
	// Extension is [ServerConfig.Extension], set by the server; nil when
	// none is configured. The authorization_code and refresh_token grants
	// call its ExtendTokenResponse between minting their tokens and
	// persisting them, and return what it adds in GrantResponse.IDToken. A
	// grant decorator forwards the request unchanged; a custom grant that
	// ignores the extension answers without its members.
	Extension Extension
}

// TokenTypeBearer is the RFC 6750 §7.1 token type issued by every grant in
// this library; it is the value of the OAuth2 token_type response field.
const TokenTypeBearer = "Bearer"

// GrantResponse is what a grant hands back to the server. The HTTP layer
// projects it onto the RFC 6749 §5.1 JSON body: the members a response may
// carry are fields — there is no free-form map, so nothing can shadow a
// standard member.
type GrantResponse struct {
	Pair      TokenPair
	Scope     string
	TokenType string // e.g. TokenTypeBearer
	// IDToken is serialized as the id_token member (OpenID Connect Core
	// §3.1.3.3) when non-empty: what the server's [Extension] added.
	IDToken string
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

// ProfileValidator is an optional [Grant] capability for grants whose
// configuration must agree with the server's [Profile]. [NewServer] calls
// ValidateProfile on every registered grant implementing it and refuses to
// build the server on error — e.g. a refresh_token grant that cannot rotate
// refresh tokens under [Profile20BCP] or [Profile21Draft]. It only moves
// the failure to boot: grants still enforce the profile at runtime through
// [GrantRequest.Profile]. Grant decorators should forward ValidateProfile;
// a grant that does not implement it is not checked at construction.
type ProfileValidator interface {
	// ValidateProfile returns why the grant cannot honor p, or nil.
	ValidateProfile(p Profile) error
}
