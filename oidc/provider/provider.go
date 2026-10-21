// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/hyperscale-stack/security/oauth2"
)

// DefaultIDTokenTTL is the ID Token lifetime (exp − iat) when
// [Config.IDTokenTTL] is zero.
const DefaultIDTokenTTL = time.Hour

// maxConfigValueLength bounds a configured claim name or acr value.
const maxConfigValueLength = 255

// Config configures a [Provider]. Keys, Claims and Interaction are
// required; every implementation MUST be safe for concurrent use.
type Config struct {
	// Keys supplies, per issuer, the ID Token signing keys and the
	// verification keys the JWK Set publishes (see [KeySource]).
	Keys KeySource
	// Claims supplies the end-user claims of ID Tokens and UserInfo, and
	// tells whether an end-user is still valid (see [ClaimsSource]).
	Claims ClaimsSource
	// Interaction is the application side of an authorization: sessions,
	// login, account selection and consent (see [Interaction]).
	Interaction Interaction
	// IDTokenTTL is the ID Token lifetime; zero means [DefaultIDTokenTTL].
	IDTokenTTL time.Duration
	// ClaimsSupported lists application claim names Discovery publishes in
	// claims_supported, after the protocol claims (Discovery §3). Their
	// spelling becomes the only one the provider releases: a case variant
	// of one (see [ClaimsSource]) is never released, so declare every claim
	// relying parties make decisions on. New refuses an entry that is a
	// claim the provider never releases (azp, jti, sid, scope, …) or a case
	// variant of a protocol, standard or other entry's claim — its part
	// before "#" included ("sub#x") —, and a language-tagged entry reading
	// as one of them or as a tagged variant of one ("email#verified", or
	// "foo#bar-fr" next to foo_bar); a protocol or standard claim spelled
	// exactly is accepted, and published once.
	ClaimsSupported []string
	// ACRValuesSupported is published as Discovery acr_values_supported —
	// omitted when empty. The provider enforces nothing about them: an acr
	// is the application's (see [AuthenticationEvent.ACR]).
	ACRValuesSupported []string
	// AllowRefreshWithoutOfflineAccess lets the grants issue refresh tokens
	// for OpenID grants the end-user did not consent to offline access for —
	// OpenID Connect Core §11's refresh tokens "in other contexts", e.g. a
	// first-party application whose refresh tokens the application ends
	// with the end-user's session. Without it, the provider fails closed: a
	// code exchange minting such a refresh token answers server_error, and
	// such a grant cannot be refreshed. The recommended wiring issues refresh
	// tokens on consented offline_access only:
	// grant.Config.RefreshTokenScope = [ScopeOfflineAccess]. The policy
	// concerns OpenID grants only: a plain OAuth 2.0 grant carries no
	// provider context, and its refresh tokens follow RefreshTokenScope
	// (see [ScopeOfflineAccess]).
	AllowRefreshWithoutOfflineAccess bool
	// AllowInsecureLoopbackIssuer accepts http issuers whose host is exactly
	// localhost or a loopback IP address — for development only: OpenID
	// Connect Core §2 requires an https issuer.
	AllowInsecureLoopbackIssuer bool
}

// validate reports why c cannot build a provider.
func (c *Config) validate() error {
	switch {
	case c.Keys == nil:
		return errors.New("oidcprovider: New: Config.Keys is required")
	case c.Claims == nil:
		return errors.New("oidcprovider: New: Config.Claims is required")
	case c.Interaction == nil:
		return errors.New("oidcprovider: New: Config.Interaction is required")
	case c.IDTokenTTL < 0:
		return errors.New("oidcprovider: New: Config.IDTokenTTL is negative")
	}

	if err := checkClaimsSupported(c.ClaimsSupported); err != nil {
		return err
	}

	for _, acr := range c.ACRValuesSupported {
		if acr == "" || len(acr) > maxConfigValueLength || !visibleASCII(acr) {
			return errors.New("oidcprovider: New: Config.ACRValuesSupported holds an invalid acr value")
		}
	}

	return nil
}

// Why New refuses Config.ClaimsSupported.
var (
	errSupportedInvalid  = errors.New("oidcprovider: New: Config.ClaimsSupported holds an invalid claim name")
	errSupportedReserved = errors.New("oidcprovider: New: Config.ClaimsSupported holds a claim the provider never releases")
	errSupportedVariant  = errors.New("oidcprovider: New: Config.ClaimsSupported holds a case variant of another claim")
)

// checkClaimsSupported refuses, in supported, an invalid claim name, a
// reserved claim — or a case variant of one — other than a protocol claim
// spelled exactly, a case variant of a known claim or of another entry
// other than its exact spelling, untagged (its untagged name) or tagged,
// a name whose part before its first "#" is one of them, and a tagged name
// that reads as one of them or as a tagged variant of one (see
// claimNames.releasable).
func checkClaimsSupported(supported []string) error {
	known := newClaimNames(nil)
	entries := map[string]string{}

	for _, name := range supported {
		if err := checkSupported(known, entries, name); err != nil {
			return err
		}
	}

	return nil
}

// checkSupported checks the ClaimsSupported entry name against the known
// claims and the entries before it, which it records.
func checkSupported(known claimNames, entries map[string]string, name string) error {
	if !validClaimName(name) {
		return errSupportedInvalid
	}

	base, tag, tagged := splitTag(name)
	prefix, _, _ := strings.Cut(name, "#")
	key, tagKey, fullKey := claimKey(base), claimKey(tag), claimKey(name)

	switch {
	case reserved(base) && slices.Contains(protocolClaims, name):
		return nil // published once among the protocol claims
	case reserved(base), reserved(prefix), tagged && continuesClaim(key, tagKey, isReservedKey):
		return errSupportedReserved
	case known.variant(base, name), known.variant(prefix, name), tagged && continuesClaim(key, tagKey, known.has):
		return errSupportedVariant
	}

	if exact, ok := entries[fullKey]; ok && exact != name {
		return errSupportedVariant
	}

	known[key], entries[fullKey] = base, name

	return nil
}

// validClaimName reports whether name may name a claim: 1 to 255 bytes of
// UTF-8 without control characters.
func validClaimName(name string) bool {
	if name == "" || len(name) > maxConfigValueLength || !utf8.ValidString(name) {
		return false
	}

	return strings.IndexFunc(name, unicode.IsControl) < 0
}

// visibleASCII reports whether s holds printable ASCII without spaces
// (%x21-7E) only.
func visibleASCII(s string) bool {
	for i := range len(s) {
		if s[i] < 0x21 || s[i] > 0x7E {
			return false
		}
	}

	return true
}

// Provider is an OpenID Provider over the oauth2.Server [New] built. It is
// safe for concurrent use and immutable once built.
type Provider struct {
	cfg    Config
	server *oauth2.Server
	// now is the server clock, shared by codes, freshness checks and ID
	// Tokens.
	now  func() time.Time
	hook oauth2.ErrorHook
	ttl  time.Duration
	// tokens is the server's storage, where UserInfo looks bearer tokens up.
	tokens oauth2.AccessTokenStore
	// clients is the server's client store: UserInfo serves the tokens of
	// clients still registered at the issuer only.
	clients oauth2.ClientStore
	// refresh reports that a refresh_token grant is registered.
	refresh bool
	// claimsSupported is the Discovery claims_supported list.
	claimsSupported []string
	// names are the claims the provider knows, by claimKey.
	names claimNames
}

// New builds an OpenID Provider on a new oauth2.Server made of server: the
// provider registers itself as the server's Extension — server.Extension
// MUST be nil — and is the only ConsentFunc of its authorization endpoint
// ([Provider.AuthorizeHandler]), so OpenID requests cannot reach an
// application callback that bypasses it. server must register the
// authorization_code grant; register refresh_token for refresh tokens and
// set grant.Config.RefreshTokenScope to [ScopeOfflineAccess] (see
// [Config.AllowRefreshWithoutOfflineAccess]). The server's clock (Now) and
// ErrorHook (OnError) are the provider's. New keeps its own copies of
// cfg's slices: changing them afterwards changes nothing.
func New(server oauth2.ServerConfig, cfg Config) (*Provider, error) {
	// Copied before they are validated: what is checked is what is served.
	cfg.ClaimsSupported = slices.Clone(cfg.ClaimsSupported)
	cfg.ACRValuesSupported = slices.Clone(cfg.ACRValuesSupported)

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	if server.Extension != nil {
		return nil, errors.New("oidcprovider: New: the server already has an Extension")
	}

	if !hasGrant(server.Grants, oauth2.GrantTypeAuthorizationCode) {
		return nil, errors.New("oidcprovider: New: the server needs the authorization_code grant")
	}

	p := &Provider{cfg: cfg, ttl: cfg.IDTokenTTL}
	if p.ttl == 0 {
		p.ttl = DefaultIDTokenTTL
	}

	server.Extension = &extension{p: p}

	srv, err := oauth2.NewServer(server)
	if err != nil {
		return nil, fmt.Errorf("oidcprovider: New: %w", err)
	}

	sc := srv.Config()
	p.server, p.now, p.hook, p.tokens, p.clients = srv, sc.Now, sc.OnError, sc.Storage, sc.ClientStore
	p.refresh = hasGrant(sc.Grants, oauth2.GrantTypeRefreshToken)
	p.claimsSupported = appendUnique(slices.Clone(protocolClaims), cfg.ClaimsSupported...)
	p.names = newClaimNames(cfg.ClaimsSupported)

	return p, nil
}

// Server returns the oauth2.Server the provider extends: mount its token,
// revocation and introspection handlers at the [Paths] of each issuer. Its
// authorization endpoint is served by [Provider.AuthorizeHandler], never by
// Server().AuthorizeHandler — the provider refuses OpenID requests that do
// not come through it.
//
// A handler built from Server().AuthorizeHandler — for plain OAuth 2.0
// requests approved by another ConsentFunc — MUST NOT enable
// AuthorizeConfig.AllowImplicit: nothing refuses it there, the server would
// serve the implicit flow to those requests, and its RFC 8414 metadata would
// advertise a flow the discovery document does not — the two publications
// would disagree (RFC 9068 §4). RFC 9700 §2.1.2 deprecates the flow.
func (p *Provider) Server() *oauth2.Server { return p.server }

// Paths are the request paths, for one issuer, at which the application
// mounts the handlers: exactly the paths of the URLs the discovery document
// of that issuer advertises (Discovery §3), so that advertised and mounted
// routes cannot drift apart. Mount them as returned — behind a proxy that
// rewrites paths, at their public form — and only there: the handlers do
// not check the request path, and a catch-all mounting would serve an
// issuer's discovery document or JWK Set at any path (Discovery §4.3).
type Paths struct {
	// Discovery is the OpenID Provider Configuration document: the issuer's
	// path, one terminating "/" removed, followed by
	// "/.well-known/openid-configuration" (Discovery §4, §4.1).
	Discovery string
	// Metadata is the RFC 8414 §3 location of the same document —
	// "/.well-known/oauth-authorization-server" inserted before the
	// issuer's path. Mounting [Provider.DiscoveryHandler] there too is
	// optional (RFC 8414 §5).
	Metadata string
	// JWKS is the JWK Set ([Provider.JWKSHandler]): the jwks_uri both
	// metadata documents advertise.
	JWKS string
	// Authorize ([Provider.AuthorizeHandler], GET and POST), Token, Revoke,
	// Introspect (Server().TokenHandler, RevokeHandler, IntrospectHandler)
	// and UserInfo ([Provider.UserInfoHandler], GET and POST) live under the
	// issuer's path and the server's RoutePrefix.
	Authorize, Token, Revoke, Introspect, UserInfo string
}

// Paths returns the [Paths] of issuer, or why issuer is not a valid issuer
// identifier ([ErrInvalidIssuer]).
func (p *Provider) Paths(issuer string) (Paths, error) {
	u, err := p.parseIssuer(issuer)
	if err != nil {
		return Paths{}, err
	}

	base := strings.TrimSuffix(u.EscapedPath(), "/")
	routes := base + p.server.Config().RoutePrefix

	return Paths{
		Discovery:  base + discoverySuffix,
		Metadata:   rfc8414Prefix + base,
		JWKS:       base + jwksSuffix,
		Authorize:  routes + "/authorize",
		Token:      routes + "/token",
		Revoke:     routes + "/revoke",
		Introspect: routes + "/introspect",
		UserInfo:   routes + "/userinfo",
	}, nil
}

// The well-known suffixes and prefix of the provider's documents.
const (
	discoverySuffix = "/.well-known/openid-configuration"
	jwksSuffix      = "/.well-known/jwks.json"
	rfc8414Prefix   = "/.well-known/oauth-authorization-server"
)

// hasGrant reports whether grants register grantType.
func hasGrant(grants []oauth2.Grant, grantType string) bool {
	for _, g := range grants {
		if g != nil && g.Type() == grantType {
			return true
		}
	}

	return false
}

// appendUnique appends to list the values it does not hold yet.
func appendUnique(list []string, values ...string) []string {
	for _, v := range values {
		if !slices.Contains(list, v) {
			list = append(list, v)
		}
	}

	return list
}

// notify hands err to the server's ErrorHook, if any.
func (p *Provider) notify(ctx context.Context, err error) {
	if p.hook != nil && err != nil {
		p.hook(ctx, err)
	}
}

// failInternal answers a request whose handling failed on the server side:
// a bare 500, the cause to the ErrorHook only — a document is never
// partially written.
func (p *Provider) failInternal(w http.ResponseWriter, r *http.Request, err error) {
	p.notify(r.Context(), oauth2.ErrServerError.WithCause(err))
	http.Error(w, "oidcprovider: internal error", http.StatusInternalServerError)
}

// allowGetHead answers 405 to a method other than GET and HEAD and reports
// whether the request may proceed.
func allowGetHead(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}

	w.Header().Set("Allow", "GET, HEAD")
	http.Error(w, "oidcprovider: method not allowed", http.StatusMethodNotAllowed)

	return false
}
