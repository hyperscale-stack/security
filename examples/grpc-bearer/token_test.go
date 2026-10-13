// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Audit CORE-I9: the demo printed a valid bearer token, good for an hour, to
// its logs. It now writes a short-lived token to a file only the current
// user can read and logs the path.
func TestWriteDemoToken(t *testing.T) {
	t.Parallel()

	path, err := writeDemoToken(t.TempDir(), "secret-token")
	require.NoError(t, err)

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	content, err := os.ReadFile(filepath.Clean(path))
	require.NoError(t, err)
	assert.Equal(t, "secret-token", string(content))

	_, err = writeDemoToken(filepath.Join(t.TempDir(), "missing"), "x")
	require.Error(t, err)
}

// Demo tokens are short-lived.
func TestDemoTokensAreShortLived(t *testing.T) {
	t.Parallel()

	assert.LessOrEqual(t, tokenLifetime, 15*time.Minute)
}
