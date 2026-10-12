// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcstack_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// forbiddenImports are the third-party OpenID Connect, OAuth 2.0 and JOSE
// libraries the tests of this module must not import: the evidence that
// our relying party and our provider interoperate must not be mediated by
// one of them. (go-jose remains, as the client's own dependency: it is part
// of the code under test.)
var forbiddenImports = []string{
	"github.com/coreos/go-oidc",
	"github.com/zitadel/oidc",
	"golang.org/x/oauth2",
	"github.com/go-jose/go-jose",
}

// TestDependencyPolicy checks the imports of every Go file of the module,
// its sub-packages included.
func TestDependencyPolicy(t *testing.T) {
	t.Parallel()

	var files []string

	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir() && d.Name() == "testdata":
			return filepath.SkipDir
		case !d.IsDir() && strings.HasSuffix(path, ".go"):
			files = append(files, path)
		}

		return nil
	})
	require.NoError(t, err)
	require.Contains(t, files, filepath.Join("conformance", "rp_test.go"), "the sub-packages are checked too")

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
