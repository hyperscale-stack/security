// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"github.com/euskadi31/go-eventemitter"
	"github.com/hyperscale-stack/logger"
	"github.com/hyperscale-stack/security/authentication/provider/oauth2/token"
)

// Option type.
type Option func(server *Server)

// WithConfig add config to server.
func WithConfig(cfg *Configuration) Option {
	return func(server *Server) {
		server.cfg = cfg
	}
}

func WithStorage(storage StorageProvider) Option {
	return func(server *Server) {
		server.storage = storage
	}
}

func WithUserProvider(userProvider UserProvider) Option {
	return func(server *Server) {
		server.userProvider = userProvider
	}
}

func WithLogger(logger logger.Logger) Option {
	return func(server *Server) {
		server.logger = logger
	}
}

func WithTokenGenerator(tokenGenerator token.Generator) Option {
	return func(server *Server) {
		server.tokenGenerator = tokenGenerator
	}
}

func WithEventEmitter(emitter eventemitter.EventEmitter) Option {
	return func(server *Server) {
		server.emitter = emitter
	}
}
