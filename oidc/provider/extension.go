// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
)

// errOpenIDNotServed refuses OpenID requests until the authorization flow
// is wired: fail closed.
var errOpenIDNotServed = errors.New("oidcprovider: OpenID authentication requests are not served yet")

// extension is the oauth2.Extension of a Provider.
type extension struct{ p *Provider }

// ValidateAuthorizeRequest implements oauth2.Extension.
func (e *extension) ValidateAuthorizeRequest(_ context.Context, _ *http.Request, ar *oauth2.AuthorizeRequest) (any, error) {
	if hasScope(ar.Scope, ScopeOpenID) {
		return nil, errOpenIDNotServed
	}

	return nil, nil
}

// CompleteAuthorization implements oauth2.Extension.
func (e *extension) CompleteAuthorization(context.Context, *oauth2.AuthorizeRequest, oauth2.Consent, time.Time) (oauth2.ExtensionGrant, error) {
	return oauth2.ExtensionGrant{}, nil
}

// ExtendTokenResponse implements oauth2.Extension.
func (e *extension) ExtendTokenResponse(context.Context, oauth2.TokenIssuance) (oauth2.TokenResponseExtension, error) {
	return oauth2.TokenResponseExtension{}, nil
}

// hasScope reports whether the space-delimited scope holds value.
func hasScope(scope, value string) bool {
	return slices.Contains(strings.Fields(scope), value)
}
