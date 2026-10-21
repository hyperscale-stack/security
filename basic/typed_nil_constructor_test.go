// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package basic_test

import (
	"testing"

	"github.com/hyperscale-stack/security/basic"
	"github.com/stretchr/testify/assert"
)

// Audit I-27: typed-nil dependencies were accepted and panicked on the
// first request.
func TestNewAuthenticatorRefusesTypedNilDependencies(t *testing.T) {
	t.Parallel()

	assert.PanicsWithValue(t, "basic: NewAuthenticator: nil UserLoader", func() {
		basic.NewAuthenticator(usersByName(nil), newHasher(t))
	})
	assert.PanicsWithValue(t, "basic: NewAuthenticator: nil password.Hasher", func() {
		basic.NewAuthenticator(unknownUsers(t), (*recordingHasher)(nil))
	})
}
