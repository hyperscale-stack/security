// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package authentication

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewTokenAuthentication(t *testing.T) {
	a := NewTokenAuthentication("my-token")

	assert.Equal(t, "my-token", a.GetPrincipal())

	assert.Nil(t, a.GetCredentials())

	assert.False(t, a.IsAuthenticated())

	a.SetAuthenticated(true)

	assert.True(t, a.IsAuthenticated())
}
