// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package memory_test

import (
	"testing"

	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	"github.com/hyperscale-stack/security/oidc/client/storage/memory"
	"github.com/hyperscale-stack/security/oidc/client/storetest"
)

// TestMemoryStoreConformance runs the shared TransactionStore contract
// against the in-memory store; the SQL and Redis stores run the same suite.
func TestMemoryStoreConformance(t *testing.T) {
	t.Parallel()

	storetest.RunConformance(t, func() oidcclient.TransactionStore { return memory.New() })
}

// TestMemoryStoreConformanceWithCapacity runs the contract against a
// bounded store: the bound changes none of its guarantees.
func TestMemoryStoreConformanceWithCapacity(t *testing.T) {
	t.Parallel()

	storetest.RunConformance(t, func() oidcclient.TransactionStore { return memory.New(memory.WithCapacity(1024)) })
}
