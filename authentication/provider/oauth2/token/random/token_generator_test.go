// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package random

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateAccessToken(t *testing.T) {
	g := NewTokenGenerator(&Configuration{
		AccessTokenSize:  128,
		RefreshTokenSize: 127,
	})

	accessToken, refreshToken, err := g.GenerateAccessToken(true)
	assert.NoError(t, err)
	assert.Equal(t, 128, len(accessToken))
	assert.Equal(t, 127, len(refreshToken))
	assert.NotEqual(t, accessToken, refreshToken)
}

func TestGenerateAccessTokenWithoutConfig(t *testing.T) {
	g := NewTokenGenerator(&Configuration{})

	accessToken, refreshToken, err := g.GenerateAccessToken(true)
	assert.NoError(t, err)
	assert.Equal(t, 128, len(accessToken))
	assert.Equal(t, 128, len(refreshToken))
	assert.NotEqual(t, accessToken, refreshToken)
}
