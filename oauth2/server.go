// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

// ClientAuthenticator is the contract the [Server] consumes for client
// authentication. Concrete implementations live in oauth2/clientauth; the
// interface lives here to avoid an import cycle. The server refuses a
// request repeating client_id or client_secret with a value before any
// method runs; an implementation reads a body parameter as its first
// non-empty occurrence (RFC 6749 §3.1: an empty one is omitted), never
// r.PostFormValue alone.
type ClientAuthenticator interface {
	Method() string
	Match(r *http.Request) bool
	Authenticate(ctx context.Context, r *http.Request, store ClientStore) (Client, error)
}

// ServerConfig bundles every dependency the [Server] needs at construction
// time. The composition root (typically main()) instantiates a ServerConfig
// once and passes it to [NewServer].
type ServerConfig struct {
	// Profile selects the security baseline (see Profile). The zero value
	// is [Profile20BCP] — the recommended default.
	Profile Profile
	// Storage is the persistence backend (codes / access tokens / refresh
	// tokens). Use storage/memory for dev/tests and store/sql or
	// store/redis for production.
	Storage Storage
	// ClientStore resolves client records by ID.
	ClientStore ClientStore
	// IssuerResolver selects the (issuer, audience) pair for each request.
	// Use [StaticIssuer] for single-tenant deployments.
	IssuerResolver IssuerResolver
	// Grants lists the grant_type handlers active on /token. The Server
	// builds a dispatch map keyed on Grant.Type(). Grants implementing
	// [ProfileValidator] are checked against Profile at construction.
	Grants []Grant
	// ClientAuth lists the client-authentication methods active on /token
	// and /revoke. The Server consults them in order and uses the first one
	// whose Match returns true. /introspect authenticates its caller through
	// the same list but answers [ClientConfidential] clients only: a public
	// client (whatever the method, "none" included) or an untyped one gets
	// 401 invalid_client.
	ClientAuth []ClientAuthenticator
	// RoutePrefix is the path prefix under which the token / revoke /
	// introspect / authorize endpoints are mounted. It is used solely to
	// build the endpoint URLs published by the RFC 8414 metadata document,
	// so the discovery document stays consistent with wherever the handlers
	// are actually mounted.
	//
	// The value is normalized at construction: an empty prefix defaults to
	// "/oauth2", a missing leading slash is added, and a trailing slash is
	// trimmed ("/" yields a root mount). The .well-known documents are not
	// affected: the metadata document lives at
	// /.well-known/oauth-authorization-server followed by the issuer's path
	// (RFC 8414 §3), and the jwks_uri it advertises is the issuer followed
	// by /.well-known/jwks.json (see [Server.MetadataHandler]).
	RoutePrefix string
	// Now is the clock used to stamp issuance / expiry, and to compute the
	// expires_in the /token response advertises. Defaults to time.Now
	// (wall clock); inject a fixed clock in tests.
	Now func() time.Time
	// OnError, when set, observes every error the server turns into an
	// RFC 6749 §5.2 response — including the cause of a server_error, which
	// never reaches the wire — plus the errors behind an answer that cannot
	// carry them (the storage failures of /revoke and /introspect, a failed
	// [IntrospectionPolicy]). Optional; see [ErrorHook].
	OnError ErrorHook
	// IntrospectionPolicy, when set, decides which active tokens of the
	// request's issuer each confidential caller of /introspect may see —
	// the place to enforce resource and tenant boundaries (RFC 7662 §4). A
	// withheld token answers {"active":false}, exactly like an unknown one.
	// Optional; nil discloses every access token to any authenticated
	// confidential client, and a refresh token to its own client only. See
	// [IntrospectionPolicy].
	IntrospectionPolicy IntrospectionPolicy
	// MaxRequestBytes bounds every request the server parses: the query
	// string and the body of /authorize, /token, /revoke and /introspect —
	// net/http alone reads up to 10 MB of form. A longer request is refused
	// with invalid_request (a bare 400 at /authorize) before any parameter
	// is read, its declared length checked before the body is. Zero or
	// negative selects [DefaultMaxRequestBytes] (64 KiB); raise it only for
	// custom grants carrying large assertions. A ConsentFunc reading the
	// body of a POST /authorize itself reads it within the same bound. A
	// body a middleware parsed before the handler (r.ParseForm,
	// r.FormValue) was read without it — only its declared length is
	// checked: bound such a middleware's reads too (http.MaxBytesReader).
	MaxRequestBytes int64
	// Extension, when set, plugs a protocol extension — an OpenID Connect
	// provider — into /authorize and into the authorization_code and
	// refresh_token exchanges of /token: see [Extension]. Optional: without
	// one the server is a plain OAuth 2.0 authorization server, and its
	// responses carry no extension member.
	Extension Extension
}

// Server is the OAuth2 authorization server. It exposes one
// http.Handler per RFC endpoint; users mount them into their router of
// choice.
type Server struct {
	cfg ServerConfig

	// dispatch maps Grant.Type() to the Grant instance for O(1) lookup
	// on /token.
	dispatch map[string]Grant

	// implicit records that an AuthorizeHandler serving the implicit flow
	// was built, for the metadata document.
	implicit atomic.Bool
}

// NewServer validates cfg and returns a ready-to-mount [Server]. It
// returns an error when the configuration is internally inconsistent
// (no storage, no client store, a grant the profile forbids or that
// rejects it through [ProfileValidator], ...).
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Storage == nil {
		return nil, errors.New("oauth2: NewServer: Storage is required")
	}

	if cfg.ClientStore == nil {
		return nil, errors.New("oauth2: NewServer: ClientStore is required")
	}

	if cfg.IssuerResolver == nil {
		return nil, errors.New("oauth2: NewServer: IssuerResolver is required")
	}

	if len(cfg.ClientAuth) == 0 {
		return nil, errors.New("oauth2: NewServer: at least one ClientAuthenticator is required")
	}

	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	cfg.RoutePrefix = normalizeRoutePrefix(cfg.RoutePrefix)

	s := &Server{cfg: cfg, dispatch: make(map[string]Grant, len(cfg.Grants))}
	for _, g := range cfg.Grants {
		if _, dup := s.dispatch[g.Type()]; dup {
			return nil, fmt.Errorf("oauth2: NewServer: duplicate grant type %q", g.Type())
		}

		s.dispatch[g.Type()] = g
	}

	if err := profileConstraints(cfg.Profile, cfg.Grants); err != nil {
		return nil, err
	}

	return s, nil
}

// Config returns the configuration the server was constructed with. Useful
// for endpoints (metadata, jwks) that need to introspect it.
func (s *Server) Config() ServerConfig { return s.cfg }

// notifyError hands err to the configured [ErrorHook], if any. It is a
// no-op when no hook is registered or when err is nil, so call sites stay
// free of guards.
func (s *Server) notifyError(ctx context.Context, err error) {
	if s.cfg.OnError == nil || err == nil {
		return
	}

	s.cfg.OnError(ctx, err)
}

// resolveIssuer wraps IssuerResolver.Resolve, translating its error to the
// canonical oauth2.Error envelope when present.
func (s *Server) resolveIssuer(ctx context.Context, r *http.Request) (string, string, error) {
	iss, aud, err := s.cfg.IssuerResolver.Resolve(ctx, r)
	if err != nil {
		return "", "", ErrServerError.WithCause(err)
	}

	return iss, aud, nil
}

// profileConstraints enforces the profile at construction: the legacy
// grants are refused outside Profile20, and every grant implementing
// [ProfileValidator] must accept the profile.
func profileConstraints(p Profile, grants []Grant) error {
	for _, g := range grants {
		switch g.Type() {
		case GrantTypePassword, GrantTypeImplicit:
			if !p.AllowsLegacyGrant() {
				return fmt.Errorf("oauth2: profile %s forbids grant %q", p, g.Type())
			}
		}

		if v, ok := g.(ProfileValidator); ok {
			if err := v.ValidateProfile(p); err != nil {
				return fmt.Errorf("oauth2: NewServer: grant %q is inconsistent with profile %s: %w", g.Type(), p, err)
			}
		}
	}

	return nil
}
