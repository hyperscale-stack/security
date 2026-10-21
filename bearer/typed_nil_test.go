// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package bearer_test

import (
	"context"
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/bearer"
	"github.com/stretchr/testify/assert"
)

type ptrVerifier struct{}

func (*ptrVerifier) Verify(context.Context, string) (security.Authentication, error) { return nil, nil }

// Audit I-27: a typed-nil verifier — bearer.VerifierFunc(nil) included —
// was accepted and panicked on the first request.
func TestNewAuthenticatorRefusesATypedNilVerifier(t *testing.T) {
	t.Parallel()

	const want = "bearer: NewAuthenticator: nil TokenVerifier"

	assert.PanicsWithValue(t, want, func() { bearer.NewAuthenticator((*ptrVerifier)(nil)) })
	assert.PanicsWithValue(t, want, func() { bearer.NewAuthenticator(bearer.VerifierFunc(nil)) })
}
