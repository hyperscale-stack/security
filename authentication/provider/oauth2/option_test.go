// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"testing"

	"github.com/hyperscale-stack/logger"
	"github.com/hyperscale-stack/security/authentication/provider/oauth2/token"
	"github.com/stretchr/testify/assert"
)

func TestWithConfig(t *testing.T) {
	cfg := &Configuration{}

	opt := WithConfig(cfg)

	server := &Server{}

	opt(server)

	assert.Same(t, cfg, server.cfg)
}

func TestWithLogger(t *testing.T) {
	logger := &logger.Nop{}

	opt := WithLogger(logger)

	server := &Server{}

	opt(server)

	assert.Same(t, logger, server.logger)
}

func TestWithStorage(t *testing.T) {
	storageMock := &MockStorageProvider{}

	opt := WithStorage(storageMock)

	server := &Server{}

	opt(server)

	assert.Same(t, storageMock, server.storage)
}

func TestWithUserProvider(t *testing.T) {
	userProviderMock := &MockUserProvider{}

	opt := WithUserProvider(userProviderMock)

	server := &Server{}

	opt(server)

	assert.Same(t, userProviderMock, server.userProvider)
}

func TestWithTokenGenerator(t *testing.T) {
	tokenGeneratorMock := &token.MockGenerator{}

	opt := WithTokenGenerator(tokenGeneratorMock)

	server := &Server{}

	opt(server)

	assert.Same(t, tokenGeneratorMock, server.tokenGenerator)
}
