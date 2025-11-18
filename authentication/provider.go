// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package authentication

import (
	"net/http"

	"github.com/hyperscale-stack/security/authentication/credential"
)

// Provider Service interface for encoding passwords
type Provider interface {
	Authenticate(r *http.Request, creds credential.Credential) (*http.Request, error)
	IsSupported(creds credential.Credential) bool
}
