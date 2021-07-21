// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package credential

import (
	"testing"

	"github.com/hyperscale-stack/security/user"
	"github.com/stretchr/testify/assert"
)

func TestNewUsernamePasswordCredential(t *testing.T) {
	a := NewUsernamePasswordCredential("my-login", "my-password")

	assert.Equal(t, "my-login", a.GetPrincipal())

	assert.Equal(t, "my-password", a.GetCredentials())

	assert.False(t, a.IsAuthenticated())

	userMock := &user.MockUser{}

	a.SetAuthenticated(true)
	a.SetUser(userMock)

	assert.True(t, a.IsAuthenticated())
	assert.Equal(t, userMock, a.GetUser())
}
