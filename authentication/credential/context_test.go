// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package credential

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContext(t *testing.T) {
	ctx := context.Background()

	creds1 := NewTokenCredential("foo")

	ctx = ToContext(ctx, creds1)

	creds2 := FromContext(ctx)

	assert.Equal(t, creds1, creds2)
}

func TestFromContextWithEmptyContext(t *testing.T) {
	ctx := context.Background()

	creds := FromContext(ctx)

	assert.Nil(t, creds)
}
