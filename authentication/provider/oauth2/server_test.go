// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestServer(t *testing.T) {
	cfg := &Configuration{}
	server := NewServer(WithConfig(cfg))

	assert.Same(t, cfg, server.cfg)
}

func TestServerNewResponse(t *testing.T) {
	cfg := &Configuration{
		ErrorStatusCode: http.StatusOK,
	}
	server := NewServer(WithConfig(cfg))

	response := server.NewResponse()
	assert.NotNil(t, response)

	assert.Equal(t, cfg.ErrorStatusCode, response.ErrorStatusCode)
}
