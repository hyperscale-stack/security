// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package credential

import (
	"testing"

	"github.com/hyperscale-stack/security/user"
	"github.com/stretchr/testify/assert"
)

func TestNewTokenCredential(t *testing.T) {
	a := NewTokenCredential("my-token")

	assert.Equal(t, "my-token", a.GetPrincipal())

	assert.Nil(t, a.GetCredentials())

	assert.False(t, a.IsAuthenticated())

	userMock := &user.MockUser{}

	a.SetAuthenticated(true)
	a.SetUser(userMock)

	assert.True(t, a.IsAuthenticated())
	assert.Equal(t, userMock, a.GetUser())
}
