// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package authorization

import "github.com/hyperscale-stack/security/authentication/credential"

// Option type.
type Option func(creds credential.Credential) bool
