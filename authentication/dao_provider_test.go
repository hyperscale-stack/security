// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package authentication

import (
	"errors"
	"testing"

	"github.com/hyperscale-stack/security/password"
	"github.com/stretchr/testify/assert"
)

func TestDaoProvider(t *testing.T) {
	ph := password.NewBCryptHasher(5)

	hash, err := ph.Hash("bar")
	assert.NoError(t, err)

	u := &MockUser{}

	u.On("GetPassword").Return(hash).Once()

	up := &MockUserProvider{}

	up.On("LoadUserByUsername", "foo").Return(u, nil).Once()

	p := NewDaoProvider(ph, up)

	a := NewUsernamePasswordAuthentication("foo", "bar")

	assert.True(t, p.IsSupported(a))

	b, err := p.Authenticate(a)
	assert.NoError(t, err)

	assert.True(t, b.IsAuthenticated())

	u.AssertExpectations(t)

	up.AssertExpectations(t)
}

func TestDaoProviderWithBadAuthentication(t *testing.T) {
	ph := password.NewBCryptHasher(5)

	hash, err := ph.Hash("bar")
	assert.NoError(t, err)

	u := &MockUser{}

	u.On("GetPassword").Return(hash)

	up := &MockUserProvider{}

	up.On("LoadUserByUsername", "foo").Return(u, nil)

	p := NewDaoProvider(ph, up)

	a := NewTokenAuthentication("foo")

	assert.False(t, p.IsSupported(a))

	b, err := p.Authenticate(a)
	assert.EqualError(t, err, "bad authentication format")

	assert.False(t, b.IsAuthenticated())

	u.AssertNotCalled(t, "GetPassword")

	up.AssertNotCalled(t, "LoadUserByUsername")
}

func TestDaoProviderWithUserNotFound(t *testing.T) {
	ph := password.NewBCryptHasher(5)

	up := &MockUserProvider{}

	up.On("LoadUserByUsername", "foo").Return(nil, errors.New("user not found")).Once()

	p := NewDaoProvider(ph, up)

	a := NewUsernamePasswordAuthentication("foo", "bar")

	assert.True(t, p.IsSupported(a))

	b, err := p.Authenticate(a)
	assert.EqualError(t, err, "user provider failed: user not found")

	assert.False(t, b.IsAuthenticated())

	up.AssertExpectations(t)
}

func TestDaoProviderWithBadPassword(t *testing.T) {
	ph := password.NewBCryptHasher(5)

	hash, err := ph.Hash("bar")
	assert.NoError(t, err)

	u := &MockUser{}

	u.On("GetPassword").Return(hash).Once()

	up := &MockUserProvider{}

	up.On("LoadUserByUsername", "foo").Return(u, nil).Once()

	p := NewDaoProvider(ph, up)

	a := NewUsernamePasswordAuthentication("foo", "bad")

	assert.True(t, p.IsSupported(a))

	b, err := p.Authenticate(a)
	assert.EqualError(t, err, "bad password")

	assert.False(t, b.IsAuthenticated())

	u.AssertExpectations(t)

	up.AssertExpectations(t)
}

func TestDaoProviderWithUserPasswordSalt(t *testing.T) {
	ph := password.NewBCryptHasher(5)

	hash, err := ph.Hash("bar:$Oo$")
	assert.NoError(t, err)

	u := &MockUserPasswordSalt{}

	u.On("GetPassword").Return(hash).Once()

	u.On("GetSalt").Return("$Oo$").Once()

	u.On("SaltPassword", "bar", "$Oo$").Return("bar:$Oo$").Once()

	up := &MockUserProvider{}

	up.On("LoadUserByUsername", "foo").Return(u, nil)

	p := NewDaoProvider(ph, up)

	a := NewUsernamePasswordAuthentication("foo", "bar")

	assert.True(t, p.IsSupported(a))

	b, err := p.Authenticate(a)
	assert.NoError(t, err)

	assert.True(t, b.IsAuthenticated())

	u.AssertExpectations(t)

	up.AssertExpectations(t)
}
