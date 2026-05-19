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
