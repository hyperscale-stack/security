// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package pkce_test

import (
	"testing"

	"github.com/hyperscale-stack/security/oauth2/pkce"
	"github.com/stretchr/testify/assert"
)

func TestMethodString(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "S256", pkce.MethodS256.String())
	assert.Equal(t, "plain", pkce.MethodPlain.String())
}
