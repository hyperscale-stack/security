// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grant

import (
	"context"

	"github.com/hyperscale-stack/security/oauth2"
)

// ResourceOwnerVerifier validates a resource owner's username / password
// for the legacy password grant. It returns the resource-owner subject
// (the value that lands in the access token's `sub`) on success.
//
// An unknown user and a wrong password MUST be indistinguishable to the
// caller — return the same error for both, so the grant cannot be used to
// enumerate accounts. Implementations live in the application layer; this
// package ships none.
type ResourceOwnerVerifier interface {
	VerifyResourceOwner(ctx context.Context, username, password string) (subject string, err error)
}

// LegacyPassword implements the RFC 6749 §4.3 Resource Owner Password
// Credentials grant.
//
// LEGACY — discouraged. This grant makes the client handle the resource
// owner's password directly; the OAuth 2.0 Security BCP and OAuth 2.1 drop
// it for exactly that reason. It is opt-in (you must add it to
// ServerConfig.Grants yourself) and [oauth2.NewServer] refuses it outside
// [oauth2.Profile20]. Use it only to migrate first-party legacy clients
// that cannot yet adopt the authorization_code flow; do not enable it for
// new deployments.
type LegacyPassword struct {
	cfg      Config
	verifier ResourceOwnerVerifier
}

// NewLegacyPassword constructs the legacy password grant. It panics when
// Storage, AccessTokens, or verifier is nil.
func NewLegacyPassword(cfg Config, verifier ResourceOwnerVerifier) *LegacyPassword {
	if cfg.Storage == nil || cfg.AccessTokens == nil {
		panic("oauth2/grant: NewLegacyPassword requires Storage and AccessTokens")
	}

	if verifier == nil {
		panic("oauth2/grant: NewLegacyPassword requires a ResourceOwnerVerifier")
	}

	return &LegacyPassword{cfg: cfg, verifier: verifier}
}

// Type implements [oauth2.Grant]. The "password" identifier is what
// oauth2.NewServer matches to refuse this grant outside Profile20.
func (g *LegacyPassword) Type() string { return "password" }

// Handle implements [oauth2.Grant].
func (g *LegacyPassword) Handle(ctx context.Context, req Request) (*Response, error) {
	if !grantTypeAllowed(req.Client, "password") {
		return nil, oauth2.ErrUnauthorizedClient.WithDescription("client cannot use the password grant")
	}

	username := req.Form.Get("username")
	password := req.Form.Get("password")

	if username == "" || password == "" {
		return nil, oauth2.ErrInvalidRequest.WithDescription("missing username or password")
	}

	subject, err := g.verifier.VerifyResourceOwner(ctx, username, password)
	if err != nil {
		// The cause stays server-side for telemetry; the client only sees
		// the generic description (anti-enumeration).
		return nil, oauth2.ErrInvalidGrant.
			WithCause(err).
			WithDescription("invalid resource owner credentials")
	}

	scope, err := narrowScopes(req.Form.Get("scope"), req.Client.Scopes())
	if err != nil {
		return nil, err
	}

	return issueTokenPair(ctx, g.cfg, req, subject, scope)
}

// Compile-time interface check.
var _ oauth2.Grant = (*LegacyPassword)(nil)
