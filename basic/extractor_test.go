// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package basic_test

import (
	"context"
	"encoding/base64"
	"net/textproto"
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/basic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mapCarrier is a minimal security.Carrier replica used by basic tests so we
// don't pull in httpsec.
type mapCarrier struct{ headers map[string][]string }

func newCarrier() *mapCarrier { return &mapCarrier{headers: make(map[string][]string)} }

func (c *mapCarrier) key(k string) string { return textproto.CanonicalMIMEHeaderKey(k) }
func (c *mapCarrier) Get(k string) string {
	vs := c.headers[c.key(k)]
	if len(vs) == 0 {
		return ""
	}

	return vs[0]
}
func (c *mapCarrier) Values(k string) []string { return c.headers[c.key(k)] }
func (c *mapCarrier) Set(k, v string)          { c.headers[c.key(k)] = []string{v} }
func (c *mapCarrier) Add(k, v string)          { c.headers[c.key(k)] = append(c.headers[c.key(k)], v) }

func encode(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestExtractorReturnsNilWhenNoAuthorizationHeader(t *testing.T) {
	t.Parallel()

	auth, err := basic.NewExtractor().Extract(context.Background(), newCarrier())
	require.NoError(t, err)
	assert.Nil(t, auth)
}

func TestExtractorReturnsNilWhenSchemeIsNotBasic(t *testing.T) {
	t.Parallel()

	c := newCarrier()
	c.Set("Authorization", "Bearer abc")

	auth, err := basic.NewExtractor().Extract(context.Background(), c)
	require.NoError(t, err)
	assert.Nil(t, auth, "non-Basic scheme MUST not be consumed")
}

func TestExtractorParsesValidBasicHeader(t *testing.T) {
	t.Parallel()

	c := newCarrier()
	c.Set("Authorization", "Basic "+encode("alice:p4ss"))

	got, err := basic.NewExtractor().Extract(context.Background(), c)
	require.NoError(t, err)
	require.NotNil(t, got)

	ba, ok := got.(basic.Authentication)
	require.True(t, ok, "Extract must return basic.Authentication")
	assert.Equal(t, "alice", ba.Username())
	assert.Equal(t, "p4ss", ba.Password())
	assert.False(t, ba.IsAuthenticated(), "extractor result is pre-authentication")
}

func TestExtractorIsCaseInsensitiveOnScheme(t *testing.T) {
	t.Parallel()

	c := newCarrier()
	c.Set("Authorization", "bAsIc "+encode("a:b"))

	got, err := basic.NewExtractor().Extract(context.Background(), c)
	require.NoError(t, err)
	assert.NotNil(t, got)
}

func TestExtractorRejectsInvalidBase64(t *testing.T) {
	t.Parallel()

	c := newCarrier()
	c.Set("Authorization", "Basic !!!")

	_, err := basic.NewExtractor().Extract(context.Background(), c)
	require.Error(t, err)
	assert.ErrorIs(t, err, security.ErrInvalidCredentials)
	assert.ErrorIs(t, err, basic.ErrBadFormat)
}

func TestExtractorRejectsMissingColon(t *testing.T) {
	t.Parallel()

	c := newCarrier()
	c.Set("Authorization", "Basic "+encode("alicepassword"))

	_, err := basic.NewExtractor().Extract(context.Background(), c)
	require.Error(t, err)
	assert.ErrorIs(t, err, security.ErrInvalidCredentials)
}

func TestExtractorPasswordCanContainColons(t *testing.T) {
	t.Parallel()

	c := newCarrier()
	c.Set("Authorization", "Basic "+encode("alice:p4:ss:word"))

	got, err := basic.NewExtractor().Extract(context.Background(), c)
	require.NoError(t, err)

	ba := got.(basic.Authentication)
	assert.Equal(t, "alice", ba.Username())
	assert.Equal(t, "p4:ss:word", ba.Password())
}

func TestExtractorEmptyUsernameAndPasswordIsAccepted(t *testing.T) {
	t.Parallel()

	c := newCarrier()
	c.Set("Authorization", "Basic "+encode(":"))

	got, err := basic.NewExtractor().Extract(context.Background(), c)
	require.NoError(t, err)

	ba := got.(basic.Authentication)
	assert.Empty(t, ba.Username())
	assert.Empty(t, ba.Password())
}
