// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"time"

	"github.com/hyperscale-stack/logger"
	"github.com/hyperscale-stack/security/authentication/provider/oauth2/token"
	"github.com/hyperscale-stack/security/authentication/provider/oauth2/token/random"
)

type Server struct {
	cfg            *Configuration
	logger         logger.Logger
	storage        StorageProvider
	userProvider   UserProvider
	tokenGenerator token.Generator
	now            func() time.Time
}

func NewServer(options ...Option) *Server {
	cfg := NewConfiguration()

	s := &Server{
		cfg:            cfg,
		logger:         &logger.Nop{},
		tokenGenerator: random.NewTokenGenerator(&random.Configuration{}),
		now:            time.Now,
	}

	for _, opt := range options {
		opt(s)
	}

	return s
}
