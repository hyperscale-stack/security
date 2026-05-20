// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package basic_test

import (
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/basic"
	"github.com/stretchr/testify/assert"
)

// fakeUser is a minimal basic.PasswordUser for the authentication tests.
type fakeUser struct{ sub string }

func (u fakeUser) Subject() string           { return u.sub }
func (u fakeUser) GetPasswordHash() string   { return "" }
func (u fakeUser) IsEnabled() bool           { return true }
func (u fakeUser) IsLocked() bool            { return false }
func (u fakeUser) IsExpired() bool           { return false }
func (u fakeUser) IsCredentialsExpired() bool { return false }

func TestAuthenticationPreAuth(t *testing.T) {
	t.Parallel()

	auth := basic.New("alice", "s3cr3t")

	assert.Equal(t, "alice", auth.Username())
	assert.Equal(t, "s3cr3t", auth.Password())
	assert.Equal(t, "alice", auth.Name())
	assert.False(t, auth.IsAuthenticated())
	assert.Nil(t, auth.Authorities())
	assert.Nil(t, auth.User())

	// Before authentication the cleartext password is the credential.
	assert.Equal(t, "s3cr3t", auth.Credentials())

	// With no resolved user the principal falls back to the anonymous one.
	assert.Equal(t, security.AnonymousPrincipal, auth.Principal())
}

func TestAuthenticationPostAuth(t *testing.T) {
	t.Parallel()

	user := fakeUser{sub: "alice"}
	auth := basic.New("alice", "s3cr3t").WithAuthenticated(user, []string{"ROLE_ADMIN"})

	assert.True(t, auth.IsAuthenticated())
	assert.Equal(t, []string{"ROLE_ADMIN"}, auth.Authorities())
	assert.Equal(t, user, auth.User())
	assert.Equal(t, user, auth.Principal())

	// The cleartext password is redacted once authenticated.
	assert.Empty(t, auth.Password())
	assert.Nil(t, auth.Credentials())
}

func TestAuthenticationEmptyPasswordHasNoCredentials(t *testing.T) {
	t.Parallel()

	// An empty password yields a nil credential without going through
	// authentication (e.g. a malformed header that produced no secret).
	assert.Nil(t, basic.New("bob", "").Credentials())
}
