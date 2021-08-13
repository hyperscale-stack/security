// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"errors"
	"time"

	"github.com/hyperscale-stack/logger"
	"github.com/hyperscale-stack/security/authentication/provider/oauth2/token"
	"github.com/hyperscale-stack/security/authentication/provider/oauth2/token/random"
)

var (
	ErrRequestMustBePost = errors.New("request must be POST")
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

// NewResponse creates a new response for the server
func (s *Server) NewResponse() *Response {
	r := NewResponse(s.storage)
	r.ErrorStatusCode = s.cfg.ErrorStatusCode

	return r
}
