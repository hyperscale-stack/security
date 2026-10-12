// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider_test

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const repo = "github.com/hyperscale-stack/security"

// TestDependencyPolicy pins the allowed dependencies of the package
// (doc.go): the standard library without its template engines, the core,
// oauth2 without its stores, and jwt — go-jose stays behind jwt, and no
// relying-party module or store driver comes in. Tests may add testify
// (testify/mock for the mocks `make generate` writes) and the oauth2
// building blocks of a server.
func TestDependencyPolicy(t *testing.T) {
	t.Parallel()

	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	require.NotEmpty(t, files)

	fset := token.NewFileSet()

	for _, name := range files {
		file, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		require.NoError(t, err)

		allowed := productionImport
		if strings.HasSuffix(name, "_test.go") {
			allowed = testImport
		}

		for _, spec := range file.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			require.NoError(t, err)
			assert.True(t, allowed(path), "%s imports %s", name, path)
		}
	}
}

func productionImport(path string) bool {
	switch {
	case path == "html/template" || path == "text/template":
		return false
	case !strings.Contains(strings.SplitN(path, "/", 2)[0], "."):
		return true // the standard library
	case path == repo || path == repo+"/jwt" || path == repo+"/oauth2" || path == repo+"/oauth2/pkce":
		return true
	default:
		return false
	}
}

func testImport(path string) bool {
	switch path {
	case repo + "/oidc/provider", repo + "/oauth2/storage/memory", repo + "/oauth2/grant", repo + "/oauth2/token",
		repo + "/oauth2/clientauth", "github.com/stretchr/testify/assert", "github.com/stretchr/testify/require",
		"github.com/stretchr/testify/mock":
		return true
	default:
		return productionImport(path)
	}
}
