// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package memory_test

import (
	"testing"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/hyperscale-stack/security/oauth2/storetest"
)

// TestMemoryStoreConformance runs the shared storage contract against the
// in-memory implementation. The same suite runs against the SQL and Redis
// stores so behavioural drift between backends fails CI.
func TestMemoryStoreConformance(t *testing.T) {
	t.Parallel()

	storetest.RunConformance(t, func() oauth2.Storage {
		return memory.New()
	})
}
