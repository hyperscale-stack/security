// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package storetest_test

import (
	"testing"

	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	"github.com/hyperscale-stack/security/oidc/client/storage/memory"
	"github.com/hyperscale-stack/security/oidc/client/storetest"
)

// TestConformanceSuiteRunsAgainstMemory exercises the conformance suite
// itself against the reference in-memory store; the SQL and Redis stores
// run the same entry point.
func TestConformanceSuiteRunsAgainstMemory(t *testing.T) {
	t.Parallel()

	storetest.RunConformance(t, func() oidcclient.TransactionStore { return memory.New() })
}
