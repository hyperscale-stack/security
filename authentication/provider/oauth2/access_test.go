// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAccessInfo(t *testing.T) {
	cat, err := time.Parse("2006-01-02T15:04:05.000Z", "2014-11-12T11:45:26.371Z")
	assert.NoError(t, err)

	ai := &AccessInfo{
		CreatedAt: cat,
		ExpiresIn: 10,
	}

	assert.True(t, ai.IsExpired())
}
