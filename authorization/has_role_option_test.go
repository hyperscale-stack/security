// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package authorization

import (
	"testing"

	"github.com/hyperscale-stack/security/authentication/credential"
	"github.com/hyperscale-stack/security/user"
	"github.com/stretchr/testify/assert"
)

func TestHasRoleWithoutUser(t *testing.T) {
	opt := HasRole("ROLE_ADMIN")

	credential := credential.NewUsernamePasswordCredential("foo", "bar")

	assert.False(t, opt(credential))
}

func TestHasRoleWithBadRole(t *testing.T) {
	opt := HasRole("ROLE_ADMIN")

	userMock := &user.MockUser{}

	userMock.On("GetRoles").Return([]string{"ROLE_USER"})

	credential := credential.NewUsernamePasswordCredential("foo", "bar")
	credential.SetUser(userMock)

	assert.False(t, opt(credential))

	userMock.AssertExpectations(t)
}

func TestHasRole(t *testing.T) {
	opt := HasRole("ROLE_ADMIN")

	userMock := &user.MockUser{}

	userMock.On("GetRoles").Return([]string{"ROLE_USER", "ROLE_ADMIN"})

	credential := credential.NewUsernamePasswordCredential("foo", "bar")
	credential.SetUser(userMock)

	assert.True(t, opt(credential))

	userMock.AssertExpectations(t)
}
