// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcstack_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// repoRoot is the repository root, from this module's directory.
var repoRoot = filepath.Join("..", "..", "..")

// The pages whose test citations TestDocumentedTestsExist checks.
var documentedPages = []string{"docs/oidc-conformance.md", "docs/oidc-client.md", "docs/oidc-provider.md"}

var (
	testDefinition = regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9_]+)\(`)
	// testCitation is a test named in backticks; a trailing * cites every
	// test with that prefix.
	testCitation = regexp.MustCompile("`(Test[A-Za-z0-9_]+)(\\*?)`")
	// certificationClaim is wording that would present the stack as
	// certified or conformant.
	certificationClaim = regexp.MustCompile(`(?i)\b(certified|conformant)\b`)
)

// definedTests returns the name of every test function of the repository.
func definedTests(t *testing.T) map[string]bool {
	t.Helper()

	defined := map[string]bool{}

	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			switch d.Name() {
			case ".git", "build", "_tools", "node_modules", "testdata":
				return filepath.SkipDir
			}

			return nil
		}

		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}

		raw, err := os.ReadFile(path) //nolint:gosec // G304: the repository's own test files
		if err != nil {
			return err
		}

		for _, m := range testDefinition.FindAllSubmatch(raw, -1) {
			defined[string(m[1])] = true
		}

		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, defined)

	return defined
}

// TestDocumentedTestsExist keeps the OpenID Connect documentation honest:
// every test the feature matrices cite exists — a renamed or deleted test
// fails here, not silently in a reader's trust — and no page presents the
// stack as certified or conformant (a local run of the OpenID Foundation
// suite is no certification).
func TestDocumentedTestsExist(t *testing.T) {
	t.Parallel()

	defined := definedTests(t)

	for _, page := range documentedPages {
		raw, err := os.ReadFile(filepath.Join(repoRoot, page)) //nolint:gosec // G304: a fixed list of pages
		require.NoError(t, err)

		citations := testCitation.FindAllSubmatch(raw, -1)
		assert.NotEmpty(t, citations, "%s cites no test", page)

		for _, c := range citations {
			name, prefix := string(c[1]), len(c[2]) > 0
			assert.True(t, defined[name] || prefix && hasPrefix(defined, name), "%s cites %s, which no test defines", page, name)
		}
	}

	pages, err := filepath.Glob(filepath.Join(repoRoot, "docs", "*.md"))
	require.NoError(t, err)

	for _, name := range []string{"README.md", "CHANGELOG.md", "LIMITATIONS.md"} {
		pages = append(pages, filepath.Join(repoRoot, name))
	}

	for _, page := range pages {
		raw, err := os.ReadFile(page) //nolint:gosec // G304: the repository's documentation
		require.NoError(t, err)

		assert.Empty(t, certificationClaim.FindAll(raw, -1), "%s claims a certification", page)
	}
}

// hasPrefix reports whether a defined test name starts with prefix.
func hasPrefix(defined map[string]bool, prefix string) bool {
	for name := range defined {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}

	return false
}
