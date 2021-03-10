// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package authentication

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewUsernamePasswordAuthentication(t *testing.T) {
	a := NewUsernamePasswordAuthentication("my-login", "my-password")

	assert.Equal(t, "my-login", a.GetPrincipal())

	assert.Equal(t, "my-password", a.GetCredentials())

	assert.False(t, a.IsAuthenticated())

	a.SetAuthenticated(true)

	assert.True(t, a.IsAuthenticated())
}
