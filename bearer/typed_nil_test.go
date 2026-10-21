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

// Review nit 7: a verifier returning a typed-nil Authentication is answered
// like one returning nil — invalid credentials (401) —, not as a broken
// contract (500).
func TestAuthenticatorRefusesATypedNilResult(t *testing.T) {
	t.Parallel()

	var typedNil *ptrAuthentication

	a := bearer.NewAuthenticator(bearer.VerifierFunc(func(context.Context, string) (security.Authentication, error) {
		return typedNil, nil
	}))

	out, err := a.Authenticate(context.Background(), bearer.New("token"))
	assert.ErrorIs(t, err, security.ErrInvalidCredentials)
	assert.Equal(t, security.Anonymous(), out)
}

// ptrAuthentication is an Authentication implemented on a pointer.
type ptrAuthentication struct{}

func (*ptrAuthentication) Principal() security.Principal { return nil }
func (*ptrAuthentication) Credentials() any              { return nil }
func (*ptrAuthentication) Authorities() []string         { return nil }
func (*ptrAuthentication) IsAuthenticated() bool         { return true }
func (*ptrAuthentication) Name() string                  { return "" }

// Audit I-27: a typed-nil verifier — bearer.VerifierFunc(nil) included —
// was accepted and panicked on the first request.
func TestNewAuthenticatorRefusesATypedNilVerifier(t *testing.T) {
	t.Parallel()

	const want = "bearer: NewAuthenticator: nil TokenVerifier"

	assert.PanicsWithValue(t, want, func() { bearer.NewAuthenticator((*ptrVerifier)(nil)) })
	assert.PanicsWithValue(t, want, func() { bearer.NewAuthenticator(bearer.VerifierFunc(nil)) })
}
