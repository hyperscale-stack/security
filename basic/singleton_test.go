// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package basic_test

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/basic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Audit CORE-I5 (probe TestZZAuditMultipleAuthorizationHeaders): with several
// Authorization fields the first one silently won (RFC 9110 §5.3).
func TestExtractorRefusesARepeatedAuthorizationField(t *testing.T) {
	t.Parallel()

	good := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:alice-secret"))
	bad := "Basic " + base64.StdEncoding.EncodeToString([]byte("root:nope"))

	for _, values := range [][]string{{good, bad}, {bad, good}, {good, "Bearer x"}} {
		c := newCarrier()
		for _, v := range values {
			c.Add("Authorization", v)
		}

		got, err := basic.NewExtractor().Extract(context.Background(), c)

		require.ErrorIs(t, err, security.ErrInvalidRequest, "%v", values)
		assert.Nil(t, got)
	}
}
