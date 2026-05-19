// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package authentication

import (
	"net/http"

	"github.com/hyperscale-stack/security/authentication/credential"
)

// Provider is the legacy credential-validation interface.
//
// Deprecated: use [security.Authenticator] (in the parent module) with the
// new HTTP middleware in github.com/hyperscale-stack/security/http.
// Scheduled for removal at the end of Phase 7.
type Provider interface {
	// Authenticate validates the legacy credential.
	//nolint:staticcheck // legacy package, scheduled removal Phase 7
	Authenticate(r *http.Request, creds credential.Credential) (*http.Request, error)
	// IsSupported reports whether this provider can handle the credential.
	//nolint:staticcheck // legacy package, scheduled removal Phase 7
	IsSupported(creds credential.Credential) bool
}
