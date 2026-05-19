// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security_test

import (
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/stretchr/testify/assert"
)

func TestAnonymousIsStableSingleton(t *testing.T) {
	t.Parallel()

	a := security.Anonymous()
	b := security.Anonymous()

	assert.Equal(t, a, b, "Anonymous() must return the same value every call")
	assert.False(t, a.IsAuthenticated())
	assert.Nil(t, a.Credentials())
	assert.Nil(t, a.Authorities())
	assert.Equal(t, "anonymous", a.Name())
	assert.Equal(t, security.AnonymousPrincipal, a.Principal())
}

func TestAnonymousPrincipalSubject(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "anonymous", security.AnonymousPrincipal.Subject())
}
