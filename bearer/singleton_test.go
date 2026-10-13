// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package bearer_test

import (
	"context"
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/bearer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Audit CORE-I5: with several Authorization fields the first one silently
// won (RFC 9110 §5.3: Authorization is a singleton field).
func TestExtractorRefusesARepeatedAuthorizationField(t *testing.T) {
	t.Parallel()

	for _, values := range [][]string{
		{"Bearer good", "Bearer other"},
		{"Bearer good", "Basic dTpw"},
	} {
		c := newCarrier()
		for _, v := range values {
			c.Add("Authorization", v)
		}

		got, err := bearer.NewExtractor().Extract(context.Background(), c)

		require.ErrorIs(t, err, security.ErrInvalidRequest, "%v", values)
		assert.Nil(t, got)
	}
}
