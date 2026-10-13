// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReasons_CoverEverySentinel: every exported sentinel of errors.go but
// ErrRejected has its own samlsp.reason (docs/observability.md), so that a
// new rejection is never reported as a bare "error".
func TestReasons_CoverEverySentinel(t *testing.T) {
	t.Parallel()

	f, err := parser.ParseFile(token.NewFileSet(), "errors.go", nil, 0)
	require.NoError(t, err)

	var sentinels []string

	ast.Inspect(f, func(n ast.Node) bool {
		if spec, ok := n.(*ast.ValueSpec); ok {
			for _, name := range spec.Names {
				if strings.HasPrefix(name.Name, "Err") {
					sentinels = append(sentinels, name.Name)
				}
			}
		}

		return true
	})

	require.NotEmpty(t, sentinels)

	o, err := parser.ParseFile(token.NewFileSet(), "otel.go", nil, 0)
	require.NoError(t, err)

	mapped := map[string]bool{}

	ast.Inspect(o, func(n ast.Node) bool {
		if lit, ok := n.(*ast.CompositeLit); ok && len(lit.Elts) == 2 {
			if id, ok := lit.Elts[0].(*ast.Ident); ok {
				mapped[id.Name] = true
			}
		}

		return true
	})

	for _, s := range sentinels {
		// ErrRejected is matched by every rejection: each one is reported
		// by its own sentinel.
		if s != "ErrRejected" {
			assert.True(t, mapped[s], "%s has no span reason in otel.go", s)
		}
	}

	names := map[string]bool{}
	for _, r := range reasons {
		assert.False(t, names[r.name], "reason %q used twice", r.name)
		names[r.name] = true
	}
}

// TestReasonName pins the reasons of the rejections added by the audit
// fixes, wrapped as CompleteLogin returns them.
func TestReasonName(t *testing.T) {
	t.Parallel()

	for sentinel, want := range map[error]string{
		ErrTransactionIntegrity: "transaction_integrity",
		ErrOriginMismatch:       "origin_mismatch",
	} {
		assert.Equal(t, want, reasonName(reject(sentinel, "", nil)))
		assert.Equal(t, want, reasonName(fmt.Errorf("samlsp: x: %w", sentinel)))
	}
}
