// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
)

// extension is the oauth2.Extension of a Provider: the hooks the server
// calls around its own checks.
type extension struct{ p *Provider }

// ValidateAuthorizeRequest implements oauth2.Extension: the OpenID
// parameters of an authorization request the core validated.
func (e *extension) ValidateAuthorizeRequest(ctx context.Context, r *http.Request, ar *oauth2.AuthorizeRequest) (any, error) {
	view, err := e.p.validateRequest(ctx, r, ar)
	if err != nil {
		return nil, err
	}

	return view, nil
}

// CompleteAuthorization implements oauth2.Extension: the verification of
// an approved decision, and the context the grant records.
func (e *extension) CompleteAuthorization(_ context.Context, ar *oauth2.AuthorizeRequest, consent oauth2.Consent, now time.Time) (oauth2.ExtensionGrant, error) {
	return e.p.completeAuthorization(ar, consent, now)
}

// ExtendTokenResponse implements oauth2.Extension: the ID Token of a code
// exchange or a refresh.
func (e *extension) ExtendTokenResponse(ctx context.Context, iss oauth2.TokenIssuance) (oauth2.TokenResponseExtension, error) {
	return e.p.extendTokenResponse(ctx, iss)
}

// hasScope reports whether the space-delimited scope holds value.
func hasScope(scope, value string) bool {
	return slices.Contains(strings.Fields(scope), value)
}
