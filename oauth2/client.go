// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"context"
	"crypto/subtle"
	"slices"
)

// The grant types a client declares in [Client.GrantTypes] — the RFC 7591
// §2 grant_types values — and the grant_type values of the shipped grants.
// An [Extension] extends the authorization_code exchange (RFC 6749 §4.1.3)
// and the refresh (§6).
const (
	// GrantTypeAuthorizationCode is the authorization-code grant (RFC 6749
	// §4.1); it also gates response_type=code at the authorization
	// endpoint (RFC 7591 §2.1).
	GrantTypeAuthorizationCode = "authorization_code"
	// GrantTypeImplicit is the legacy implicit grant (RFC 6749 §4.2): it
	// gates response_type=token at the authorization endpoint (RFC 7591
	// §2.1). No grant_type of the token endpoint carries it.
	GrantTypeImplicit = "implicit"
	// GrantTypeRefreshToken is the refresh-token grant (RFC 6749 §6).
	GrantTypeRefreshToken = "refresh_token"
	// GrantTypeClientCredentials is the client-credentials grant (RFC 6749
	// §4.4).
	GrantTypeClientCredentials = "client_credentials"
	// GrantTypePassword is the legacy resource-owner password grant (RFC
	// 6749 §4.3).
	GrantTypePassword = "password"
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
	// GrantTypes lists the grant types the client may use, compared exactly
	// with RFC 7591 §2 values — the GrantType constants
	// ("authorization_code", "implicit", "refresh_token",
	// "client_credentials", "password") or a custom grant's type. An empty
	// list allows no grant: nothing is implied, unlike the RFC 7591 §2
	// registration default (authorization_code). See
	// [ClientAllowsGrantType].
	GrantTypes() []string
	// Scopes lists the scopes the client may request, compared exactly (RFC
	// 6749 §3.3: case-sensitive). An empty list allows no scope: a request
	// carrying one is refused with invalid_scope, and one without scope
	// gets the empty scope. A scope outside the RFC 6749 §3.3 syntax
	// (printable ASCII but '"' and '\\', no space) can never be requested.
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
//
// One store serving an [IssuerResolver] with several issuers makes every
// client known at every issuer: a deployment where each client belongs to
// one realm (tenant) gives its clients the [IssuerBoundClient] capability,
// or scopes its store by issuer itself.
type ClientStore interface {
	LoadClient(ctx context.Context, id string) (Client, error)
}

// IssuerBoundClient is an optional capability of a [Client] registered at
// some issuers only — the realms an [IssuerResolver] serves from one
// [ClientStore]. Without it a client of one realm can use every other one:
// send the end-users of realm B to B's login page, and obtain their codes
// and tokens.
//
// The server checks it at every issuer it resolves, before trusting
// anything the client presents: at another issuer the client does not
// exist. /authorize answers it as it answers an unknown client_id — a bare
// 400 that is never redirected (RFC 6749 §4.1.2.1: the client identifier is
// invalid here, and so are its redirect URIs) — and /token, /revoke and
// /introspect fail its authentication as they fail an unknown client's —
// 401 invalid_client, "unknown client" (RFC 6749 §5.2), whatever the
// secret presented — so another realm's clients can be neither enumerated
// nor their secrets checked. unauthorized_client is not used: it would
// confirm an authenticated, existing client. The [ErrorHook] gets
// [ErrClientNotAtIssuer] as the cause. A server whose IssuerResolver fails
// cannot check it: the request then fails with server_error, nothing
// issued.
type IssuerBoundClient interface {
	// AllowsIssuer reports whether the client is registered at issuer, the
	// identifier the IssuerResolver returned — compared exactly (OpenID
	// Connect Core §16.15: issuers are compared as strings). It MUST be
	// fast and safe for concurrent use.
	AllowsIssuer(issuer string) bool
}

// ClientAllowsIssuer reports whether c may be used at issuer: what its
// [IssuerBoundClient] capability says, true without the capability.
func ClientAllowsIssuer(c Client, issuer string) bool {
	if bound, ok := c.(IssuerBoundClient); ok {
		return bound.AllowsIssuer(issuer)
	}

	return true
}

// ClientAllowsGrantType reports whether c may use grantType: one of its
// [Client.GrantTypes], compared exactly. A client declaring none may use no
// grant — the fail-closed default: register what each client needs. The
// token endpoint checks it for every grant type before the grant runs,
// custom grants included; the authorization endpoint for the grant of the
// response type (GrantTypeAuthorizationCode for code, GrantTypeImplicit for
// token); and the shipped grants check it again when called directly.
func ClientAllowsGrantType(c Client, grantType string) bool {
	return slices.Contains(c.GrantTypes(), grantType)
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
	//
	// A DefaultClient prints and logs without it (String, Format,
	// LogValue).
	Secret            string //nolint:gosec // dev/test convenience
	TypeValue         ClientType
	RedirectURIValues []string
	// GrantTypeValues lists the grant types the client may use (see
	// [Client.GrantTypes]): empty, none.
	GrantTypeValues []string
	// ScopeValues lists the scopes the client may request (see
	// [Client.Scopes]): empty, none.
	ScopeValues      []string
	AuthMethodValues []string
	// IssuerValues lists the issuers the client is registered at (see
	// [IssuerBoundClient]); empty: every issuer the server resolves.
	IssuerValues []string
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

// AllowsIssuer implements [IssuerBoundClient]: the issuers listed in
// IssuerValues, compared exactly — every issuer when none is listed.
func (c *DefaultClient) AllowsIssuer(issuer string) bool {
	return len(c.IssuerValues) == 0 || slices.Contains(c.IssuerValues, issuer)
}

// Compile-time interface checks.
var (
	_ Client            = (*DefaultClient)(nil)
	_ SecretMatcher     = (*DefaultClient)(nil)
	_ IssuerBoundClient = (*DefaultClient)(nil)
)
