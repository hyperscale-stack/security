// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package authentication

import "github.com/hyperscale-stack/security/authentication/credential"

// Provider Service interface for encoding passwords
//go:generate mockery --name=Provider --inpackage --case underscore
type Provider interface {
	Authenticate(creds credential.Credential) error
	IsSupported(creds credential.Credential) bool
}
