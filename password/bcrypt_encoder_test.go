// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package password

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

func TestBCryptEncoderEncode(t *testing.T) {
	e := NewBCryptEncoder(10)

	hash, err := e.Encode("foo")
	assert.NoError(t, err)

	cost, err := bcrypt.Cost([]byte(hash))
	assert.NoError(t, err)

	assert.Equal(t, 10, cost)

	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte("foo"))
	assert.NoError(t, err)
}
