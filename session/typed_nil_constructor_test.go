// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session_test

import (
	"context"
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/session"
	"github.com/stretchr/testify/assert"
)

type ptrLoader struct{}

func (*ptrLoader) Load(context.Context, map[string]any) (security.Principal, []string, error) {
	return nil, nil, nil
}

// Audit I-27: a typed-nil loader, and a nil Manager given to NewExtractor,
// were accepted and panicked on the first request.
func TestConstructorsRefuseTypedNilDependencies(t *testing.T) {
	t.Parallel()

	assert.PanicsWithValue(t, "session: NewAuthenticator: nil PrincipalLoader",
		func() { session.NewAuthenticator((*ptrLoader)(nil)) })
	assert.PanicsWithValue(t, "session: NewExtractor: nil Manager", func() { session.NewExtractor(nil) })
}
