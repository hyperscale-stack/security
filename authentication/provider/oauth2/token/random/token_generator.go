// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package random

import (
	"github.com/hyperscale-stack/secure"
	"github.com/hyperscale-stack/security/authentication/provider/oauth2/token"
)

var _ token.Generator = (*TokenGenerator)(nil)

type TokenGenerator struct {
	cfg *Configuration
}

func NewTokenGenerator(cfg *Configuration) token.Generator {
	if cfg.AccessTokenSize == 0 {
		cfg.AccessTokenSize = 128
	}

	if cfg.RefreshTokenSize == 0 {
		cfg.RefreshTokenSize = 128
	}

	return &TokenGenerator{
		cfg: cfg,
	}
}

func (g *TokenGenerator) GenerateAccessToken(generateRefresh bool) (accessToken string, refreshToken string, err error) {
	accessToken, err = secure.GenerateRandomString(g.cfg.AccessTokenSize)

	if generateRefresh {
		refreshToken, err = secure.GenerateRandomString(g.cfg.RefreshTokenSize)
	}

	return
}
