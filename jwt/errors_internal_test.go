// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrAlgorithmDisallowed(t *testing.T) {
	t.Parallel()

	err := &errAlgorithmDisallowed{alg: "HS256"}

	assert.Equal(t, `jwt: algorithm "HS256" not allowed`, err.Error())
	// The sentinel chain bridges to ErrAlgorithmNotAllowed.
	assert.ErrorIs(t, err, ErrAlgorithmNotAllowed)
}

func TestAsAlgorithmName(t *testing.T) {
	t.Parallel()

	// A direct errAlgorithmDisallowed yields its algorithm name.
	name, ok := AsAlgorithmName(&errAlgorithmDisallowed{alg: "ES512"})
	assert.True(t, ok)
	assert.Equal(t, "ES512", name)

	// A wrapped one is still found via errors.As.
	wrapped := fmt.Errorf("verify failed: %w", &errAlgorithmDisallowed{alg: "none"})
	name, ok = AsAlgorithmName(wrapped)
	assert.True(t, ok)
	assert.Equal(t, "none", name)

	// An unrelated error yields ("", false).
	name, ok = AsAlgorithmName(errors.New("something else"))
	assert.False(t, ok)
	assert.Empty(t, name)
}
