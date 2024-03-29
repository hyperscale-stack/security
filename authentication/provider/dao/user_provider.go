// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package dao

import "github.com/hyperscale-stack/security/user"

// UserProvider interface which loads user-specific data.
//go:generate mockery --name=UserProvider --inpackage --case underscore
type UserProvider interface {
	LoadUserByUsername(username string) (user.User, error)
}
