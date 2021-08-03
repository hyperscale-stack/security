// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

// Option type.
type Option func(server *Server)

// WithConfig add config to server
func WithConfig(cfg *Configuration) Option {
	return func(server *Server) {
		server.cfg = cfg
	}
}

func WithStorage(storage StorageProvider) Option {
	return func(server *Server) {

	}
}
