// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManagerReturnsUnsupportedWhenNoAuthenticator(t *testing.T) {
	m := security.NewManager()
	auth := newFakeAuth("alice")

	got, err := m.Authenticate(context.Background(), auth)

	assert.ErrorIs(t, err, security.ErrUnsupportedCredential)
	assert.Equal(t, Authentication(auth), got, "input MUST flow through on failure")
}

func TestManagerReturnsUnsupportedWhenNoAuthenticatorSupports(t *testing.T) {
	a := &scriptedAuthenticator{
		name:     "noop",
		supports: func(Authentication) bool { return false },
	}
	m := security.NewManager(a)

	_, err := m.Authenticate(context.Background(), newFakeAuth("alice"))

	assert.ErrorIs(t, err, security.ErrUnsupportedCredential)
	assert.Zero(t, a.calls(), "Authenticate must not be called when Supports is false")
}

func TestManagerFirstSuccessWins(t *testing.T) {
	authenticated := newFakeAuth("alice").withAuthenticated()

	first := &scriptedAuthenticator{name: "first", result: authenticated}
	second := &scriptedAuthenticator{name: "second", result: newFakeAuth("bob").withAuthenticated()}

	m := security.NewManager(first, second)

	got, err := m.Authenticate(context.Background(), newFakeAuth("alice"))

	require.NoError(t, err)
	assert.Equal(t, Authentication(authenticated), got)
	assert.Equal(t, 1, first.calls())
	assert.Zero(t, second.calls(), "second authenticator MUST NOT be consulted after success")
}

func TestManagerFailoverWhenSupportingAuthenticatorRefuses(t *testing.T) {
	winning := newFakeAuth("alice").withAuthenticated()
	first := &scriptedAuthenticator{name: "first", err: security.ErrInvalidCredentials}
	second := &scriptedAuthenticator{name: "second", result: winning}

	m := security.NewManager(first, second)

	got, err := m.Authenticate(context.Background(), newFakeAuth("alice"))

	require.NoError(t, err)
	assert.Equal(t, Authentication(winning), got)
	assert.Equal(t, 1, first.calls())
	assert.Equal(t, 1, second.calls())
}

func TestManagerAggregatesErrorsWhenAllRefuse(t *testing.T) {
	first := &scriptedAuthenticator{name: "first", err: security.ErrInvalidCredentials}
	second := &scriptedAuthenticator{name: "second", err: security.ErrTokenExpired}

	m := security.NewManager(first, second)

	_, err := m.Authenticate(context.Background(), newFakeAuth("alice"))

	require.Error(t, err)
	assert.ErrorIs(t, err, security.ErrAuthenticatorRefused)
	assert.ErrorIs(t, err, security.ErrInvalidCredentials)
	assert.ErrorIs(t, err, security.ErrTokenExpired)
}

func TestManagerSpanCarriesAuthenticatorName(t *testing.T) {
	winning := newFakeAuth("alice").withAuthenticated()
	a := &scriptedAuthenticator{name: "winner", result: winning}

	m := security.NewManager(a)

	spans := spanRecorder(func() {
		_, err := m.Authenticate(context.Background(), newFakeAuth("alice"))
		require.NoError(t, err)
	})

	require.Len(t, spans, 1)
	span := spans[0]

	assert.Equal(t, "security.Manager.Authenticate", span.Name())
	assert.Equal(t, "true", findAttr(span.Attributes(), security.AttrAuthenticated))
	assert.Equal(t, "winner", findAttr(span.Attributes(), security.AttrAuthenticatorName))
}

func TestManagerSpanRecordsErrorOnRefuseAll(t *testing.T) {
	a := &scriptedAuthenticator{name: "x", err: errors.New("boom")}

	m := security.NewManager(a)

	spans := spanRecorder(func() {
		_, err := m.Authenticate(context.Background(), newFakeAuth("alice"))
		assert.Error(t, err)
	})

	require.Len(t, spans, 1)
	assert.Equal(t, "Error", spans[0].Status().Code.String())
}

func TestManagerSafeForConcurrentUse(t *testing.T) {
	winning := newFakeAuth("alice").withAuthenticated()
	a := &scriptedAuthenticator{name: "winner", result: winning}
	m := security.NewManager(a)

	var (
		wg     sync.WaitGroup
		errors = make(chan error, 50)
	)

	for range 50 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			_, err := m.Authenticate(context.Background(), newFakeAuth("alice"))
			if err != nil {
				errors <- err
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Fatalf("unexpected error: %v", err)
	}
}
