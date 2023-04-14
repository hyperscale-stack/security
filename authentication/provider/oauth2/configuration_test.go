// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAllowedAuthorizeType(t *testing.T) {
	types := AllowedAuthorizeType{CODE}

	assert.True(t, types.Exists(CODE))
	assert.False(t, types.Exists(TOKEN))
}

func TestAllowedAccessType(t *testing.T) {
	types := AllowedAccessType{AUTHORIZATION_CODE, CLIENT_CREDENTIALS}

	assert.True(t, types.Exists(AUTHORIZATION_CODE))
	assert.True(t, types.Exists(CLIENT_CREDENTIALS))
	assert.False(t, types.Exists(ASSERTION))
}
