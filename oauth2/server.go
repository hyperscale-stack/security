// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// ClientAuthenticator is the contract the [Server] consumes for client
// authentication. Concrete implementations live in oauth2/clientauth; the
// interface lives here to avoid an import cycle.
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
	// tokens). Use storage/memory for dev/tests and storage/sql or
	// storage/redis for production (Phase 8).
	Storage Storage
	// ClientStore resolves client records by ID.
	ClientStore ClientStore
	// IssuerResolver selects the (issuer, audience) pair for each request.
	// Use [StaticIssuer] for single-tenant deployments.
	IssuerResolver IssuerResolver
	// Grants lists the grant_type handlers active on /token. The Server
	// builds a dispatch map keyed on Grant.Type().
	Grants []Grant
	// ClientAuth lists the client-authentication methods active on /token
	// (and /revoke, /introspect). The Server consults them in order and
	// uses the first one whose Match returns true.
	ClientAuth []ClientAuthenticator
	// Now is the clock used to stamp issuance / expiry. Defaults to
	// time.Now (wall clock); inject a fixed clock in tests.
	Now func() time.Time
}

// Server is the OAuth2 authorization server. It exposes one
// http.Handler per RFC endpoint; users mount them into their router of
// choice.
type Server struct {
	cfg ServerConfig

	// dispatch maps Grant.Type() to the Grant instance for O(1) lookup
	// on /token.
	dispatch map[string]Grant
}

// NewServer validates cfg and returns a ready-to-mount [Server]. It
// returns an error when the configuration is internally inconsistent
// (no storage, no client store, ...).
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

// authenticateClient runs the configured client-authentication methods in
// order and returns the first match.
func (s *Server) authenticateClient(ctx context.Context, r *http.Request) (Client, error) {
	for _, m := range s.cfg.ClientAuth {
		if !m.Match(r) {
			continue
		}

		c, err := m.Authenticate(ctx, r, s.cfg.ClientStore)
		if err != nil {
			return nil, fmt.Errorf("oauth2.Server: client auth: %w", err)
		}

		return c, nil
	}

	return nil, ErrInvalidClient.WithDescription("no client authentication method matched")
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

// profileConstraints enforces the profile-specific bans (e.g. legacy
// grants refused outside Profile20).
func profileConstraints(p Profile, grants []Grant) error {
	if p.AllowsLegacyGrant() {
		return nil
	}

	for _, g := range grants {
		switch g.Type() {
		case "password", "implicit":
			return fmt.Errorf("oauth2: profile %s forbids grant %q", p, g.Type())
		}
	}

	return nil
}
