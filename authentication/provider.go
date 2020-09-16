// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package authentication

// Provider Service interface for encoding passwords
type Provider interface {
	Authenticate(authentication Authentication) (Authentication, error)
	IsSupported(authentication Authentication) bool
}
