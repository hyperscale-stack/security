// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp_test

import (
	"testing"

	samlsp "github.com/hyperscale-stack/security/saml/sp"
	"github.com/hyperscale-stack/security/saml/sp/storage/memory"
	"github.com/stretchr/testify/mock"
)

// storageDouble returns the generated MockStorage of a test, every method
// delegating to mem — a real store, so the double keeps state — unless
// first registered an expectation of its own for it: testify answers a
// call with the first expectation that matches.
func storageDouble(t *testing.T, mem *memory.Store, first func(m *samlsp.MockStorage)) *samlsp.MockStorage {
	t.Helper()

	m := samlsp.NewMockStorage(t)

	if first != nil {
		first(m)
	}

	m.EXPECT().SaveTransaction(mock.Anything, mock.Anything).RunAndReturn(mem.SaveTransaction).Maybe()
	m.EXPECT().LookupTransaction(mock.Anything, mock.Anything).RunAndReturn(mem.LookupTransaction).Maybe()
	m.EXPECT().ConsumeTransaction(mock.Anything, mock.Anything, mock.Anything).RunAndReturn(mem.ConsumeTransaction).Maybe()
	m.EXPECT().MarkAssertionUsed(mock.Anything, mock.Anything, mock.Anything).RunAndReturn(mem.MarkAssertionUsed).Maybe()

	return m
}

// withStorage makes the env use store for transactions and replays.
func withStorage(store samlsp.Storage) envOption {
	return func(c *samlsp.Config, _ *samlsp.Connection) { c.Transactions, c.ReplayCache = store, store }
}
