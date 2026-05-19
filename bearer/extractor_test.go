// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package bearer_test

import (
	"context"
	"net/textproto"
	"testing"

	"github.com/hyperscale-stack/security/bearer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mapCarrier is a minimal security.Carrier replica for bearer tests.
type mapCarrier struct{ vals map[string][]string }

func newCarrier() *mapCarrier { return &mapCarrier{vals: make(map[string][]string)} }

func (c *mapCarrier) key(k string) string { return textproto.CanonicalMIMEHeaderKey(k) }
func (c *mapCarrier) Get(k string) string {
	if vs := c.vals[c.key(k)]; len(vs) > 0 {
		return vs[0]
	}

	return ""
}
func (c *mapCarrier) Values(k string) []string { return c.vals[c.key(k)] }
func (c *mapCarrier) Set(k, v string)          { c.vals[c.key(k)] = []string{v} }
func (c *mapCarrier) Add(k, v string)          { c.vals[c.key(k)] = append(c.vals[c.key(k)], v) }

func TestExtractorReturnsNilWhenHeaderAbsent(t *testing.T) {
	t.Parallel()

	got, err := bearer.NewExtractor().Extract(context.Background(), newCarrier())
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestExtractorReturnsNilForNonBearerSchemes(t *testing.T) {
	t.Parallel()

	c := newCarrier()
	c.Set("Authorization", "Basic xxx")

	got, err := bearer.NewExtractor().Extract(context.Background(), c)
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestExtractorParsesBearerHeader(t *testing.T) {
	t.Parallel()

	c := newCarrier()
	c.Set("Authorization", "Bearer eyJabc.def.ghi")

	got, err := bearer.NewExtractor().Extract(context.Background(), c)
	require.NoError(t, err)
	require.NotNil(t, got)

	ba := got.(bearer.Authentication)
	assert.Equal(t, "eyJabc.def.ghi", ba.Token())
	assert.False(t, ba.IsAuthenticated())
}

func TestExtractorCaseInsensitiveOnScheme(t *testing.T) {
	t.Parallel()

	c := newCarrier()
	c.Set("Authorization", "bearer abc")

	got, err := bearer.NewExtractor().Extract(context.Background(), c)
	require.NoError(t, err)
	assert.NotNil(t, got)
}

func TestExtractorIgnoresEmptyToken(t *testing.T) {
	t.Parallel()

	c := newCarrier()
	c.Set("Authorization", "Bearer ")

	got, err := bearer.NewExtractor().Extract(context.Background(), c)
	require.NoError(t, err)
	assert.Nil(t, got, "Bearer with empty token must let downstream extractors try")
}

func TestQueryExtractorParsesNamedParameter(t *testing.T) {
	t.Parallel()

	c := newCarrier()
	c.Set("access_token", "deadbeef")

	got, err := bearer.NewQueryExtractor("").Extract(context.Background(), c)
	require.NoError(t, err)
	require.NotNil(t, got)

	ba := got.(bearer.Authentication)
	assert.Equal(t, "deadbeef", ba.Token())
}

func TestQueryExtractorReturnsNilWhenAbsent(t *testing.T) {
	t.Parallel()

	got, err := bearer.NewQueryExtractor("custom_token").Extract(context.Background(), newCarrier())
	require.NoError(t, err)
	assert.Nil(t, got)
}
