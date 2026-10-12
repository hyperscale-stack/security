// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"context"
	"net/http"
)

// IssuerResolver returns the issuer identifier (and matching audience) for
// the request being processed. The interface lets multi-tenant deployments
// dispatch on the Host header or a routing prefix without baking the
// tenant into every grant handler.
//
// The issuer is the realm of a grant: /authorize records it with the
// authorization code, and every token records it; the authorization_code
// and refresh_token grants refuse, with invalid_grant, a code or refresh
// token issued under another issuer than the one resolved for the /token
// request (OIDC Core §16.15: a subject is only meaningful within its
// issuer). A resolver MUST therefore return the same issuer for every
// request of one realm — /authorize, /token — and issuers are compared
// exactly. Changing an issuer invalidates the outstanding codes and
// refresh tokens issued under the former one.
type IssuerResolver interface {
	Resolve(ctx context.Context, r *http.Request) (issuer, audience string, err error)
}

// StaticIssuer returns an [IssuerResolver] that always returns the
// configured (issuer, audience) pair. The canonical single-tenant setup.
func StaticIssuer(issuer, audience string) IssuerResolver {
	return staticIssuer{issuer: issuer, audience: audience}
}

type staticIssuer struct {
	issuer   string
	audience string
}

// Resolve implements [IssuerResolver].
func (s staticIssuer) Resolve(context.Context, *http.Request) (string, string, error) {
	return s.issuer, s.audience, nil
}
