// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package storetest_test

import (
	"testing"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/hyperscale-stack/security/oauth2/storetest"
)

// TestConformanceSuiteRunsAgainstMemory exercises the shared conformance
// suite itself: running it against the reference in-memory store both
// validates that store and proves the harness is internally sound. The SQL
// and Redis modules run the same RunConformance entry point.
func TestConformanceSuiteRunsAgainstMemory(t *testing.T) {
	t.Parallel()

	storetest.RunConformance(t, func() oauth2.Storage {
		return memory.New()
	})
}
