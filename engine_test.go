// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security_test

import (
	"context"
	"errors"
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEngineReturnsErrNoExtractorWhenNoneConfigured(t *testing.T) {
	e := security.NewEngine(security.NewManager())

	ctx, auth, err := e.Process(context.Background(), newMapCarrier())

	assert.ErrorIs(t, err, security.ErrNoExtractor)
	assert.Equal(t, security.Anonymous(), auth)

	got, _ := security.FromContext(ctx)
	assert.Equal(t, security.Anonymous(), got, "context must carry Anonymous on error")
}

func TestEngineFallsThroughToAnonymousWhenNoExtractorFinds(t *testing.T) {
	first := scriptedExtractor{}  // (nil, nil) -> "did not apply"
	second := scriptedExtractor{} // same

	e := security.NewEngine(security.NewManager(), first, second)

	ctx, auth, err := e.Process(context.Background(), newMapCarrier())

	require.NoError(t, err)
	assert.Equal(t, security.Anonymous(), auth)
	got, _ := security.FromContext(ctx)
	assert.Equal(t, security.Anonymous(), got,
		"Engine stores Anonymous explicitly so downstream code can always read it")
}

func TestEngineShortCircuitsOnExtractorError(t *testing.T) {
	boom := errors.New("malformed header")

	first := scriptedExtractor{err: boom}
	second := &countingExtractor{}

	e := security.NewEngine(security.NewManager(), first, second)

	_, _, err := e.Process(context.Background(), newMapCarrier())

	assert.ErrorIs(t, err, boom)
	assert.Zero(t, second.calls, "subsequent extractors must not run after an error")
}

func TestEngineHandsExtractedToManager(t *testing.T) {
	pending := newFakeAuth("alice").withCredentials("p4ssw0rd")
	authed := newFakeAuth("alice").withAuthenticated()

	extractor := scriptedExtractor{auth: pending}
	authn := &scriptedAuthenticator{name: "basic", result: authed}

	e := security.NewEngine(security.NewManager(authn), extractor)

	ctx, got, err := e.Process(context.Background(), newMapCarrier())

	require.NoError(t, err)
	assert.Equal(t, Authentication(authed), got)
	stored, ok := security.FromContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, Authentication(authed), stored)
}

func TestEnginePropagatesManagerError(t *testing.T) {
	pending := newFakeAuth("alice").withCredentials("bad")
	extractor := scriptedExtractor{auth: pending}
	authn := &scriptedAuthenticator{name: "basic", err: security.ErrInvalidCredentials}

	e := security.NewEngine(security.NewManager(authn), extractor)

	ctx, got, err := e.Process(context.Background(), newMapCarrier())

	assert.ErrorIs(t, err, security.ErrInvalidCredentials)
	assert.Equal(t, Authentication(pending), got,
		"failed auth returns the pre-authentication value so adapters can craft a challenge")
	stored, _ := security.FromContext(ctx)
	assert.Equal(t, Authentication(pending), stored)
}

func TestEngineSpanRecordsExtractorAndAuthenticationFlags(t *testing.T) {
	authed := newFakeAuth("alice").withAuthenticated()
	extractor := scriptedExtractor{auth: newFakeAuth("alice").withCredentials("ok")}
	authn := &scriptedAuthenticator{name: "basic", result: authed}

	e := security.NewEngine(security.NewManager(authn), extractor, scriptedExtractor{})

	spans := spanRecorder(func() {
		_, _, err := e.Process(context.Background(), newMapCarrier())
		require.NoError(t, err)
	})

	require.GreaterOrEqual(t, len(spans), 1)

	var engineSpan int = -1

	for i, s := range spans {
		if s.Name() == "security.Engine.Process" {
			engineSpan = i

			break
		}
	}

	require.GreaterOrEqual(t, engineSpan, 0, "engine span must be emitted")
	span := spans[engineSpan]
	assert.Equal(t, "2", findAttr(span.Attributes(), security.AttrExtractorsCount))
	assert.Equal(t, "true", findAttr(span.Attributes(), security.AttrAuthenticated))
}
