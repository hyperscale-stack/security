// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func TestErrorClass(t *testing.T) {
	t.Parallel()

	refused := func(causes ...error) error {
		return fmt.Errorf("%w: %w", security.ErrAuthenticatorRefused, errors.Join(causes...))
	}
	plain := errors.New("sql: connection refused")

	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ""},
		{"invalid request", security.ErrInvalidRequest, security.ErrorClassInvalidRequest},
		{"unavailable", security.ErrUnavailable, security.ErrorClassUnavailable},
		{"token expired", security.ErrTokenExpired, security.ErrorClassTokenExpired},
		{"token not found", security.ErrTokenNotFound, security.ErrorClassTokenNotFound},
		{"client secret mismatch", security.ErrClientSecretMismatch, security.ErrorClassClientSecretMismatch},
		{"invalid credentials", security.ErrInvalidCredentials, security.ErrorClassInvalidCredentials},
		{"authentication required", security.ErrAuthenticationRequired, security.ErrorClassAuthenticationRequired},
		{"unsupported credential", security.ErrUnsupportedCredential, security.ErrorClassUnsupportedCredential},
		{"insufficient scope", security.ErrInsufficientScope, security.ErrorClassInsufficientScope},
		{"access denied", security.ErrAccessDenied, security.ErrorClassAccessDenied},
		{"no extractor", security.ErrNoExtractor, security.ErrorClassNoExtractor},
		{"no sentinel", plain, security.ErrorClassOther},
		{"bare refusal", security.ErrAuthenticatorRefused, security.ErrorClassOther},
		{"refusal of a plain error", refused(plain), security.ErrorClassOther},
		{"wrapped verdict", fmt.Errorf("jwt: invalid audience: %w", security.ErrInvalidCredentials),
			security.ErrorClassInvalidCredentials},
		{"refusal of a verdict", refused(fmt.Errorf("basic: %w", security.ErrInvalidCredentials)),
			security.ErrorClassInvalidCredentials},
		// A malformed request is refused whatever else happened.
		{"invalid request before unavailable", errors.Join(security.ErrUnavailable, security.ErrInvalidRequest),
			security.ErrorClassInvalidRequest},
		// An outage is not a verdict: a joined refusal of another
		// authenticator must not tell the client to drop its credential.
		{"unavailable before a verdict", refused(security.ErrTokenNotFound, security.ErrUnavailable),
			security.ErrorClassUnavailable},
		{"basic loader outage", fmt.Errorf("basic: load user: %w (%w)", security.ErrUnavailable, security.ErrInvalidCredentials),
			security.ErrorClassUnavailable},
		// One authenticator's refusal is not masked by another's bail-out.
		{"verdict before unsupported", errors.Join(security.ErrUnsupportedCredential, security.ErrInvalidCredentials),
			security.ErrorClassInvalidCredentials},
		{"expired before invalid", errors.Join(security.ErrInvalidCredentials, security.ErrTokenExpired),
			security.ErrorClassTokenExpired},
		// An unauthenticated principal refused by a decision is asked to
		// authenticate (401), not refused (403).
		{"authentication required before access denied",
			fmt.Errorf("%w: %w", security.ErrAuthenticationRequired, security.ErrAccessDenied),
			security.ErrorClassAuthenticationRequired},
		{"insufficient scope before access denied",
			fmt.Errorf("%w: %w", security.ErrInsufficientScope, security.ErrAccessDenied),
			security.ErrorClassInsufficientScope},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, c.want, security.ErrorClass(c.err))
		})
	}
}

// failureSpanEvidence collects, for the spans of fn, every string a trace
// backend would store about a failure: status descriptions, event names and
// attribute values.
func failureSpanEvidence(spans []sdktrace.ReadOnlySpan) string {
	var b strings.Builder

	for _, s := range spans {
		b.WriteString(s.Status().Description + "\n")

		for _, kv := range s.Attributes() {
			b.WriteString(kv.Value.Emit() + "\n")
		}

		for _, ev := range s.Events() {
			b.WriteString(ev.Name + "\n")

			for _, kv := range ev.Attributes {
				b.WriteString(kv.Value.Emit() + "\n")
			}
		}
	}

	return b.String()
}

func spanNamed(t *testing.T, spans []sdktrace.ReadOnlySpan, name string) sdktrace.ReadOnlySpan {
	t.Helper()

	for _, s := range spans {
		if s.Name() == name {
			return s
		}
	}

	require.Failf(t, "span not found", "%s", name)

	return nil
}

// Audit probe TestZZAuditSpansCarryAuthenticatorErrorText: the Engine and
// Manager spans carried the authenticators' error text (a password typed in
// the username field, a wrapped store error) as status and exception event.
func TestEngineSpanRecordsTheErrorClassNotTheMessage(t *testing.T) {
	const typed = "MyP@ssw0rd-typed-in-user-field"

	authn := security.AuthenticatorFunc(func(context.Context, security.Authentication) (security.Authentication, error) {
		return nil, fmt.Errorf("basic: load user %q: %w (%w)", typed,
			errors.New("sql: no rows for email alice@example.com"), security.ErrInvalidCredentials)
	})
	engine := security.NewEngine(security.NewManager(authn), scriptedExtractor{auth: newFakeAuth(typed).withCredentials("x")})

	spans := spanRecorder(func() {
		_, _, err := engine.Process(context.Background(), newMapCarrier())
		require.Error(t, err)
	})

	evidence := failureSpanEvidence(spans)
	assert.NotContains(t, evidence, typed)
	assert.NotContains(t, evidence, "alice@example.com")
	assert.NotContains(t, evidence, "sql:")
	assert.NotContains(t, evidence, "exception", "no exception event: its message is the error text")

	for _, name := range []string{"security.Engine.Process", "security.Manager.Authenticate"} {
		span := spanNamed(t, spans, name)
		assert.Equal(t, codes.Error, span.Status().Code, name)
		assert.Equal(t, security.ErrorClassInvalidCredentials, span.Status().Description, name)
		assert.Equal(t, security.ErrorClassInvalidCredentials, findAttr(span.Attributes(), security.AttrErrorType), name)
	}
}

func TestEngineSpanRecordsTheClassOfAnExtractorError(t *testing.T) {
	const secret = "Basic dXNlcjpTM2NyM3Qh"

	engine := security.NewEngine(security.NewManager(),
		scriptedExtractor{err: fmt.Errorf("basic: bad header %q: %w", secret, security.ErrInvalidCredentials)})

	spans := spanRecorder(func() {
		_, _, err := engine.Process(context.Background(), newMapCarrier())
		require.Error(t, err)
	})

	assert.NotContains(t, failureSpanEvidence(spans), secret)

	span := spanNamed(t, spans, "security.Engine.Process")
	assert.Equal(t, security.ErrorClassInvalidCredentials, span.Status().Description)
	assert.Equal(t, security.ErrorClassInvalidCredentials, findAttr(span.Attributes(), security.AttrErrorType))
}

func TestFailureSpansRecordTheirClass(t *testing.T) {
	cases := []struct {
		name, span, class string
		run               func() error
	}{
		{"no extractor", "security.Engine.Process", security.ErrorClassNoExtractor, func() error {
			_, _, err := security.NewEngine(security.NewManager()).Process(context.Background(), newMapCarrier())

			return err
		}},
		{"unsupported", "security.Manager.Authenticate", security.ErrorClassUnsupportedCredential, func() error {
			_, err := security.NewManager().Authenticate(context.Background(), newFakeAuth("alice"))

			return err
		}},
		{"plain refusal", "security.Manager.Authenticate", security.ErrorClassOther, func() error {
			_, err := security.NewManager(&scriptedAuthenticator{name: "x", err: errors.New("boom")}).
				Authenticate(context.Background(), newFakeAuth("alice"))

			return err
		}},
		{"denied", "security.AccessDecisionManager.Decide", security.ErrorClassAccessDenied, func() error {
			return security.NewAffirmativeDecisionManager(constDecisionVoter{d: security.DecisionDeny}).
				Decide(context.Background(), newFakeAuth("alice").withAuthenticated(), []security.Attribute{stringAttr("x")})
		}},
	}

	for _, c := range cases {
		spans := spanRecorder(func() { require.Error(t, c.run(), c.name) })

		span := spanNamed(t, spans, c.span)
		assert.Equal(t, codes.Error, span.Status().Code, c.name)
		assert.Equal(t, c.class, span.Status().Description, c.name)
		assert.Equal(t, c.class, findAttr(span.Attributes(), security.AttrErrorType), c.name)

		for _, ev := range span.Events() {
			assert.NotEqual(t, "exception", ev.Name, c.name)
		}
	}
}

func TestSuccessfulSpansCarryNoErrorType(t *testing.T) {
	authed := newFakeAuth("alice").withAuthenticated()
	engine := security.NewEngine(security.NewManager(&scriptedAuthenticator{name: "ok", result: authed}),
		scriptedExtractor{auth: newFakeAuth("alice")})
	adm := security.NewAffirmativeDecisionManager(constDecisionVoter{d: security.DecisionGrant})

	spans := spanRecorder(func() {
		_, _, err := engine.Process(context.Background(), newMapCarrier())
		require.NoError(t, err)
		require.NoError(t, adm.Decide(context.Background(), authed, []security.Attribute{stringAttr("x")}))
	})

	require.Len(t, spans, 3)

	for _, s := range spans {
		assert.Empty(t, findAttr(s.Attributes(), security.AttrErrorType), s.Name())
		assert.NotEqual(t, codes.Error, s.Status().Code, s.Name())
	}
}
