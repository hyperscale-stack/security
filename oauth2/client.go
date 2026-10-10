// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"context"
	"crypto/subtle"
)

// ClientType describes whether an OAuth2 client is capable of safely keeping
// a secret (confidential) or runs in an environment where it cannot
// (public). Public clients MUST use PKCE per OAuth 2.0 BCP §2.1.1.
type ClientType string

const (
	// ClientConfidential is a client that can keep a secret (server-side
	// applications, machine-to-machine services).
	ClientConfidential ClientType = "confidential"
	// ClientPublic is a client that cannot keep a secret (browser apps,
	// native mobile apps).
	ClientPublic ClientType = "public"
)

// Client is the OAuth2 client record stored in the [ClientStore]. The
// interface is intentionally small; implementations decide how to source the
// data (in-memory, database, federated registry).
type Client interface {
	// ID is the public client identifier.
	ID() string
	// Type reports whether the client is confidential or public.
	Type() ClientType
	// RedirectURIs lists the redirect URIs registered by the client.
	// Authorization code requests MUST match one of these exactly per
	// RFC 6749 §3.1.2.3 / OAuth 2.0 BCP §2.1.4.
	RedirectURIs() []string
	// GrantTypes lists the grant types the client is allowed to use.
	// Compared with strings.EqualFold; common values are
	// "authorization_code", "refresh_token", "client_credentials".
	GrantTypes() []string
	// Scopes lists the maximum set of scopes the client may request. An
	// empty list means "no scope restriction" and SHOULD be reserved for
	// internal clients only.
	Scopes() []string
	// AuthMethods lists the client_authentication_method values supported
	// for this client (see clientauth package). "none" implies a public
	// client.
	AuthMethods() []string
}

// SecretMatcher is the optional capability used by confidential client
// authentication methods (client_secret_basic, client_secret_post) to
// verify the registered secret without exposing it. Implementations MUST
// use constant-time comparison (or a hashed-secret scheme).
//
// An empty secret is never a credential: implementations MUST NOT match
// it — not even against a hash of the empty string — nor anything when no
// secret is registered.
type SecretMatcher interface {
	// SecretMatches returns true when secret matches the registered one.
	// Implementations MUST use constant-time comparison, and MUST return
	// false when secret is empty or no secret is registered.
	SecretMatches(secret string) bool
}

// ClientStore loads client records by ID. Implementations are responsible
// for caching policy; the Server invokes LoadClient once per request that
// needs client authentication.
type ClientStore interface {
	LoadClient(ctx context.Context, id string) (Client, error)
}

// DefaultClient is a minimal in-memory [Client] implementation handy for
// tests, examples, and small static deployments. Production deployments
// SHOULD plug a database-backed Client implementation instead.
type DefaultClient struct {
	IDValue string
	// Secret is the cleartext client secret. DefaultClient stores it
	// verbatim for dev/test convenience; production deployments wrap a
	// hashed-secret store and implement SecretMatches themselves.
	//
	// Leave it empty for a client that does not authenticate with a secret
	// (a public client using "none", or a client authenticated by another
	// method): an empty Secret matches nothing, so client_secret_basic and
	// client_secret_post never authenticate it.
	Secret            string //nolint:gosec // dev/test convenience
	TypeValue         ClientType
	RedirectURIValues []string
	GrantTypeValues   []string
	ScopeValues       []string
	AuthMethodValues  []string
}

// ID implements [Client].
func (c *DefaultClient) ID() string { return c.IDValue }

// Type implements [Client].
func (c *DefaultClient) Type() ClientType { return c.TypeValue }

// RedirectURIs implements [Client].
func (c *DefaultClient) RedirectURIs() []string { return c.RedirectURIValues }

// GrantTypes implements [Client].
func (c *DefaultClient) GrantTypes() []string { return c.GrantTypeValues }

// Scopes implements [Client].
func (c *DefaultClient) Scopes() []string { return c.ScopeValues }

// AuthMethods implements [Client].
func (c *DefaultClient) AuthMethods() []string { return c.AuthMethodValues }

// SecretMatches implements [SecretMatcher] using constant-time comparison.
// An empty Secret registers no secret and matches nothing, the empty string
// included. The DefaultClient stores secrets in cleartext for development
// convenience; production deployments SHOULD wrap a hashed-secret store and
// implement SecretMatches themselves.
func (c *DefaultClient) SecretMatches(secret string) bool {
	if c.Secret == "" {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(c.Secret), []byte(secret)) == 1
}

// Compile-time interface checks.
var (
	_ Client        = (*DefaultClient)(nil)
	_ SecretMatcher = (*DefaultClient)(nil)
)
