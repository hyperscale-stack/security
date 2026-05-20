// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grpcsec_test

import (
	"context"
	"testing"

	grpcsec "github.com/hyperscale-stack/security/grpc"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/metadata"
)

func TestCarrierReads(t *testing.T) {
	t.Parallel()

	ctx := metadata.NewIncomingContext(context.Background(), metadata.MD{
		"authorization": {"Bearer one", "Bearer two"},
	})
	c := grpcsec.NewCarrier(ctx)

	// gRPC lowercases metadata keys; the carrier lower-cases lookups so the
	// conventional "Authorization" spelling resolves.
	assert.Equal(t, "Bearer one", c.Get("Authorization"))
	assert.Equal(t, []string{"Bearer one", "Bearer two"}, c.Values("Authorization"))
	assert.Empty(t, c.Values("x-absent"))
}

func TestCarrierWritesResponseMetadata(t *testing.T) {
	t.Parallel()

	c := grpcsec.NewCarrier(context.Background())

	c.Set("x-trace", "abc")
	c.Add("x-trace", "def")

	md := c.ResponseMetadata()
	assert.Equal(t, []string{"abc", "def"}, md.Get("x-trace"))
}
