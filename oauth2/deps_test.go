// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestModuleRequiresNoOIDCOrJOSE pins the dependency policy of the oauth2
// module: plain OAuth2 consumers never pull an OpenID Connect or JOSE
// library — an OpenID provider plugs in through oauth2.Extension from its
// own module. A package cannot import what its module does not require, so
// the go.mod is the whole proof.
func TestModuleRequiresNoOIDCOrJOSE(t *testing.T) {
	t.Parallel()

	gomod, err := os.ReadFile("go.mod")
	require.NoError(t, err)

	for _, forbidden := range []string{
		"go-jose", "jose", "jwt", "oidc", "golang.org/x/oauth2", "zitadel",
		"hyperscale-stack/security/jwt", "hyperscale-stack/security/oidc",
	} {
		assert.NotContains(t, strings.ToLower(string(gomod)), forbidden)
	}
}
