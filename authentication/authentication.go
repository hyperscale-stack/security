// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package authentication

// Authentication interface
type Authentication interface {
	GetPrincipal() interface{}
	GetCredentials() interface{}
	IsAuthenticated() bool
	SetAuthenticated(isAuthenticated bool)
}
