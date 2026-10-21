// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package basic_test

import (
	"context"
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/basic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// usersByName returns the stored *stubUser — nil for an unknown name — as
// a basic.PasswordUser: the one-liner `return m[name], nil` over a map of
// pointers returns a typed nil for every unknown name.
type usersByName map[string]*stubUser

func (m usersByName) LoadByUsername(_ context.Context, name string) (basic.PasswordUser, error) {
	return m[name], nil
}

// Audit F-16: a typed-nil user passed the `user != nil` check and
// GetPasswordHash dereferenced it — one unauthenticated request crashed a
// gRPC server. A typed nil is an unknown user: verified against the dummy
// hash, refused like any unknown account.
func TestAuthenticatorTreatsATypedNilUserAsUnknown(t *testing.T) {
	t.Parallel()

	hasher := &recordingHasher{match: "alice-hash"}
	a := basic.NewAuthenticator(usersByName{"alice": {subject: "alice", passwordHash: "alice-hash", enabled: true}}, hasher)
	baseline := len(hasher.calls())

	var (
		out security.Authentication
		err error
	)

	require.NotPanics(t, func() { out, err = a.Authenticate(context.Background(), basic.New("nobody", "right")) })

	require.ErrorIs(t, err, security.ErrInvalidCredentials)
	assert.ErrorContains(t, err, "basic: user not found", "the server-side cause names an unknown user")
	assert.Equal(t, security.ErrorClassInvalidCredentials, security.ErrorClass(err))
	assert.Equal(t, security.Anonymous(), out)
	assert.Equal(t, []string{"dummy-1"}, hasher.calls()[baseline:], "one verification, against the dummy hash")

	out, err = a.Authenticate(context.Background(), basic.New("alice", "right"))
	require.NoError(t, err)
	assert.Equal(t, "alice", out.Name())
}
