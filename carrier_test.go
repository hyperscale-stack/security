// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security_test

import (
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Audit CORE-I5: RFC 9110 §5.3 forbids repeating a singleton field such as
// Authorization (§11.6.2); reading the first value silently ignored the
// others.
func TestSingleValue(t *testing.T) {
	t.Parallel()

	c := newMapCarrier()

	v, err := security.SingleValue(c, "Authorization")
	require.NoError(t, err)
	assert.Empty(t, v, "absent")

	c.Add("Authorization", "")
	v, err = security.SingleValue(c, "Authorization")
	require.NoError(t, err)
	assert.Empty(t, v, "present but empty")

	c.Set("Authorization", "Bearer one")
	v, err = security.SingleValue(c, "Authorization")
	require.NoError(t, err)
	assert.Equal(t, "Bearer one", v)

	c.Add("Authorization", "Bearer two")
	v, err = security.SingleValue(c, "Authorization")
	require.ErrorIs(t, err, security.ErrInvalidRequest)
	assert.Empty(t, v)
	assert.Equal(t, `security: header field "Authorization" occurs 2 times: security: invalid authentication request`, err.Error())
}
