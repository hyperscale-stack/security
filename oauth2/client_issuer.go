// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/hyperscale-stack/security/oauth2/internal/param"
)

// issuerClients is the [ClientStore] a request sees at its issuer: a
// client bound to other issuers ([IssuerBoundClient]) does not exist
// there, and neither does an identifier longer than [MaxClientIDLength],
// which is never looked up. One instance serves one request.
type issuerClients struct {
	store  ClientStore
	issuer string
	// anyIssuer reports that the issuer is unknown — the IssuerResolver
	// failed — so the binding cannot be checked: the request fails anyway.
	anyIssuer bool
	// hidden records that a client bound to other issuers was hidden: the
	// cause of the refusal that follows.
	hidden bool
}

// LoadClient implements [ClientStore].
func (c *issuerClients) LoadClient(ctx context.Context, id string) (Client, error) {
	if len(id) > MaxClientIDLength {
		return nil, nil
	}

	client, err := c.store.LoadClient(ctx, id)
	if err != nil || client == nil || c.anyIssuer {
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
// handed is checked again on its result. A request carrying its client's
// credentials more than once is refused first (singleCredential), and one
// whose body client_id names another client than the one authenticated
// after.
func (s *Server) authenticateClient(ctx context.Context, r *http.Request, issuer string) (Client, error) {
	if oe := singleCredential(r); oe != nil {
		return nil, oe
	}

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

		// RFC 6749 §3.2.1 lets a client name itself with client_id: never
		// another client than the one authenticated.
		if id := param.Value(r.PostForm, paramClientID); id != "" && id != c.ID() {
			return nil, errClientIDMismatch
		}

		return c, nil
	}

	return nil, ErrInvalidClient.WithDescription("no client authentication method matched")
}

// The refusals of a request authenticating its client more than once: RFC
// 6749 §2.3 ("The client MUST NOT use more than one authentication method
// in each request") and §5.2 (invalid_request: "includes multiple
// credentials, utilizes more than one mechanism for authenticating the
// client").
var (
	errSeveralAuthorizations = ErrInvalidRequest.WithDescription("more than one Authorization header")
	errSeveralAuthMethods    = ErrInvalidRequest.WithDescription("more than one client authentication method")
	errClientIDMismatch      = ErrInvalidRequest.WithDescription("client_id does not name the authenticated client")
)

// singleCredential refuses, before any client is loaded, a request that
// carries client credentials more than once: a client_id or client_secret
// repeated with a value, several Authorization fields (RFC 9110 §5.3: a
// field that is not a list is not repeated), or an Authorization header and
// a client_secret in the body.
func singleCredential(r *http.Request) *Error {
	if _, repeated := param.SingleValued(r.PostForm, clientAuthParameters); repeated != "" {
		return repeatedParameter(repeated)
	}

	switch authorization := r.Header.Values("Authorization"); {
	case len(authorization) > 1:
		return errSeveralAuthorizations
	case len(authorization) == 1 && authorization[0] != "" && param.Value(r.PostForm, paramClientSecret) != "":
		return errSeveralAuthMethods
	default:
		return nil
	}
}

// errUnknownClient is how client authentication answers an unknown client
// (oauth2/clientauth): a client of another issuer reads the same.
var errUnknownClient = ErrInvalidClient.WithDescription("unknown client")
