// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// logged renders v the ways an application may log it.
func logged(v any) string {
	var buf bytes.Buffer

	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	logger.Info("value", "v", v)

	return fmt.Sprintf("%v|%+v|%#v|%s|", v, v, v, v) + buf.String()
}

func TestSecretsAreRedacted(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	c := op.client(t)
	ar, code := op.begin(t, c, oidcclient.AuthOptions{})

	out := logged(*ar)
	assert.NotContains(t, out, ar.Binding)
	assert.Contains(t, out, "REDACTED")
	assert.NotContains(t, logged(ar), ar.Binding)

	cb := callbackFor(ar, code)
	out = logged(cb)
	assert.NotContains(t, out, ar.Binding)
	assert.NotContains(t, out, code)
	assert.NotContains(t, out, ar.State)

	id, err := c.Complete(context.Background(), cb)
	require.NoError(t, err)

	for _, rendered := range []string{logged(id.Tokens), logged(*id), logged(id)} {
		assert.NotContains(t, rendered, id.Tokens.AccessToken)
		assert.NotContains(t, rendered, id.Tokens.RefreshToken)
		assert.NotContains(t, rendered, id.Tokens.IDToken)
	}
}

func TestDefaultClock(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	c := op.client(t, func(cfg *oidcclient.Config) { cfg.Now = nil })

	ar, err := c.Begin(context.Background(), oidcclient.AuthOptions{})
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(oidcclient.DefaultTransactionTTL), ar.ExpiresAt, 2*time.Second)
}

func TestDecodeClaimsError(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	id, err := op.login(t, op.client(t))
	require.NoError(t, err)

	var wrong struct {
		Sub int `json:"sub"`
	}

	require.Error(t, id.DecodeClaims(&wrong))
}
