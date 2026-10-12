// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

// issuerClients is the [ClientStore] a request sees at its issuer: a
// client bound to other issuers ([IssuerBoundClient]) does not exist
// there. One instance serves one request.
type issuerClients struct {
	store  ClientStore
	issuer string
	// hidden records that a client bound to other issuers was hidden: the
	// cause of the refusal that follows.
	hidden bool
}

// LoadClient implements [ClientStore].
func (c *issuerClients) LoadClient(ctx context.Context, id string) (Client, error) {
	client, err := c.store.LoadClient(ctx, id)
	if err != nil || client == nil {
		return client, err //nolint:wrapcheck // the store's own answer, unchanged
	}

	if !ClientAllowsIssuer(client, c.issuer) {
		c.hidden = true

		return nil, nil
	}

	return client, nil
}

// explain adds [ErrClientNotAtIssuer] to the cause of oe when the request
// met a client bound to other issuers: the ErrorHook learns why, the wire
// still reads as an unknown client.
func (c *issuerClients) explain(oe *Error) *Error {
	if c == nil || !c.hidden {
		return oe
	}

	return oe.WithCause(ErrClientNotAtIssuer)
}

// authenticateClientAt resolves the issuer of r, then authenticates its
// client at that issuer — a client bound to other issuers is unknown there
// — and returns the client, the issuer and the audience the resolver gave.
func (s *Server) authenticateClientAt(ctx context.Context, r *http.Request) (Client, string, string, error) {
	issuer, audience, err := s.resolveIssuer(ctx, r)
	if err != nil {
		return nil, "", "", err
	}

	client, err := s.authenticateClient(ctx, r, issuer)
	if err != nil {
		return nil, "", "", err
	}

	return client, issuer, audience, nil
}

// authenticateClient runs the configured client-authentication methods in
// order and returns the first match, the clients of other issuers hidden.
// An authenticator that does not load the client through the store it is
// handed is checked again on its result.
func (s *Server) authenticateClient(ctx context.Context, r *http.Request, issuer string) (Client, error) {
	clients := &issuerClients{store: s.cfg.ClientStore, issuer: issuer}

	for _, m := range s.cfg.ClientAuth {
		if !m.Match(r) {
			continue
		}

		c, err := m.Authenticate(ctx, r, clients)
		if err != nil {
			var oe *Error
			if errors.As(err, &oe) && oe != nil {
				return nil, clients.explain(oe)
			}

			return nil, fmt.Errorf("oauth2.Server: client auth: %w", err)
		}

		if c == nil || !ClientAllowsIssuer(c, issuer) {
			return nil, errUnknownClient.WithCause(ErrClientNotAtIssuer)
		}

		return c, nil
	}

	return nil, ErrInvalidClient.WithDescription("no client authentication method matched")
}

// errUnknownClient is how client authentication answers an unknown client
// (oauth2/clientauth): a client of another issuer reads the same.
var errUnknownClient = ErrInvalidClient.WithDescription("unknown client")
