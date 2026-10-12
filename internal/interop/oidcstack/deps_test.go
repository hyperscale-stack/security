// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcstack_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// forbiddenImports are the third-party OpenID Connect, OAuth 2.0 and JOSE
// libraries this module must not use: the evidence that our relying party
// and our provider interoperate must not be mediated by one of them.
var forbiddenImports = []string{
	"github.com/coreos/go-oidc",
	"github.com/zitadel/oidc",
	"golang.org/x/oauth2",
	"github.com/go-jose/go-jose",
}

// TestDependencyPolicy checks the imports of every file of the module.
func TestDependencyPolicy(t *testing.T) {
	t.Parallel()

	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	require.NotEmpty(t, files)

	fset := token.NewFileSet()

	for _, file := range files {
		src, err := os.ReadFile(file)
		require.NoError(t, err)

		f, err := parser.ParseFile(fset, file, src, parser.ImportsOnly)
		require.NoError(t, err)

		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			require.NoError(t, err)

			for _, forbidden := range forbiddenImports {
				assert.False(t, strings.HasPrefix(path, forbidden), "%s imports %s", file, path)
			}
		}
	}
}
