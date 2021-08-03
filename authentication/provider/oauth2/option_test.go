// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWithConfig(t *testing.T) {
	cfg := &Configuration{}

	opt := WithConfig(cfg)

	server := &Server{}

	opt(server)

	assert.Same(t, cfg, server.cfg)
}
