// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package storetest_test

import (
	"testing"

	samlsp "github.com/hyperscale-stack/security/saml/sp"
	"github.com/hyperscale-stack/security/saml/sp/storage/memory"
	"github.com/hyperscale-stack/security/saml/sp/storetest"
)

// TestRunConformanceOnMemory exercises the suite itself against the
// reference in-memory store.
func TestRunConformanceOnMemory(t *testing.T) {
	t.Parallel()

	storetest.RunConformance(t, func() samlsp.Storage { return memory.New() })
}
