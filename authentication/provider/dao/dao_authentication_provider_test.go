// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package dao

import (
	"errors"
	"net/http"
	"testing"

	"github.com/hyperscale-stack/security/authentication/credential"
	"github.com/hyperscale-stack/security/password"
	"github.com/hyperscale-stack/security/user"
	"github.com/stretchr/testify/assert"
)

func TestDaoAuthenticationProvider(t *testing.T) {
	ph := password.NewBCryptHasher(5)

	hash, err := ph.Hash("bar")
	assert.NoError(t, err)

	u := &user.MockUser{}

	u.On("GetPassword").Return(hash).Once()

	up := &MockUserProvider{}

	up.On("LoadUserByUsername", "foo").Return(u, nil).Once()

	p := NewDaoAuthenticationProvider(ph, up)

	c := credential.NewUsernamePasswordCredential("foo", "bar")

	assert.True(t, p.IsSupported(c))

	r, err := http.NewRequest(http.MethodGet, "", nil)
	assert.NoError(t, err)

	err = p.Authenticate(r, c)
	assert.NoError(t, err)

	assert.True(t, c.IsAuthenticated())

	u.AssertExpectations(t)

	up.AssertExpectations(t)
}

func TestDaoAuthenticationProviderWithBadAuthentication(t *testing.T) {
	ph := password.NewBCryptHasher(5)

	hash, err := ph.Hash("bar")
	assert.NoError(t, err)

	u := &user.MockUser{}

	u.On("GetPassword").Return(hash)

	up := &MockUserProvider{}

	up.On("LoadUserByUsername", "foo").Return(u, nil)

	p := NewDaoAuthenticationProvider(ph, up)

	c := credential.NewTokenCredential("foo")

	assert.False(t, p.IsSupported(c))

	r, err := http.NewRequest(http.MethodGet, "", nil)
	assert.NoError(t, err)

	err = p.Authenticate(r, c)
	assert.EqualError(t, err, "bad authentication format")

	assert.False(t, c.IsAuthenticated())

	u.AssertNotCalled(t, "GetPassword")

	up.AssertNotCalled(t, "LoadUserByUsername")
}

func TestDaoAuthenticationProviderWithUserNotFound(t *testing.T) {
	ph := password.NewBCryptHasher(5)

	up := &MockUserProvider{}

	up.On("LoadUserByUsername", "foo").Return(nil, errors.New("user not found")).Once()

	p := NewDaoAuthenticationProvider(ph, up)

	c := credential.NewUsernamePasswordCredential("foo", "bar")

	assert.True(t, p.IsSupported(c))

	r, err := http.NewRequest(http.MethodGet, "", nil)
	assert.NoError(t, err)

	err = p.Authenticate(r, c)
	assert.EqualError(t, err, "user provider failed: user not found")

	assert.False(t, c.IsAuthenticated())

	up.AssertExpectations(t)
}

func TestDaoAuthenticationProviderWithBadPassword(t *testing.T) {
	ph := password.NewBCryptHasher(5)

	hash, err := ph.Hash("bar")
	assert.NoError(t, err)

	u := &user.MockUser{}

	u.On("GetPassword").Return(hash).Once()

	up := &MockUserProvider{}

	up.On("LoadUserByUsername", "foo").Return(u, nil).Once()

	p := NewDaoAuthenticationProvider(ph, up)

	c := credential.NewUsernamePasswordCredential("foo", "bad")

	assert.True(t, p.IsSupported(c))

	r, err := http.NewRequest(http.MethodGet, "", nil)
	assert.NoError(t, err)

	err = p.Authenticate(r, c)
	assert.EqualError(t, err, "bad password")

	assert.False(t, c.IsAuthenticated())

	u.AssertExpectations(t)

	up.AssertExpectations(t)
}

func TestDaoAuthenticationProviderWithUserPasswordSalt(t *testing.T) {
	ph := password.NewBCryptHasher(5)

	hash, err := ph.Hash("bar:$Oo$")
	assert.NoError(t, err)

	u := &user.MockUserPasswordSalt{}

	u.On("GetPassword").Return(hash).Once()

	u.On("GetSalt").Return("$Oo$").Once()

	u.On("SaltPassword", "bar", "$Oo$").Return("bar:$Oo$").Once()

	up := &MockUserProvider{}

	up.On("LoadUserByUsername", "foo").Return(u, nil)

	p := NewDaoAuthenticationProvider(ph, up)

	c := credential.NewUsernamePasswordCredential("foo", "bar")

	assert.True(t, p.IsSupported(c))

	r, err := http.NewRequest(http.MethodGet, "", nil)
	assert.NoError(t, err)

	err = p.Authenticate(r, c)
	assert.NoError(t, err)

	assert.True(t, c.IsAuthenticated())

	u.AssertExpectations(t)

	up.AssertExpectations(t)
}
