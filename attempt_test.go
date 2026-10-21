// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/netip"
	"testing"
	"time"

	"github.com/hyperscale-stack/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTooManyAttemptsErrorWrapsItsSentinel(t *testing.T) {
	t.Parallel()

	var err error = &security.TooManyAttemptsError{RetryAfter: 90 * time.Second}

	require.ErrorIs(t, err, security.ErrTooManyAttempts)
	assert.NotErrorIs(t, err, security.ErrInvalidCredentials, "a throttle is not a verdict on the credentials")
	assert.NotErrorIs(t, err, security.ErrUnavailable, "a throttle is not an outage")

	var marker security.SecurityError

	require.ErrorAs(t, err, &marker, "the error type carries the SecurityError marker itself")

	var tooMany *security.TooManyAttemptsError

	require.ErrorAs(t, fmt.Errorf("basic: %w", err), &tooMany)
	assert.Equal(t, 90*time.Second, tooMany.RetryAfter)
	assert.Equal(t, security.ErrorClassTooManyAttempts, security.ErrorClass(err))
}

func TestTooManyAttemptsErrorText(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "security: too many failed authentication attempts",
		(&security.TooManyAttemptsError{}).Error())
	assert.Equal(t, "security: too many failed authentication attempts (retry in 2s)",
		(&security.TooManyAttemptsError{RetryAfter: 1500 * time.Millisecond}).Error(),
		"the delay is rounded up to the second, never down to zero")
	assert.Equal(t, "security: too many failed authentication attempts (retry in 1s)",
		(&security.TooManyAttemptsError{RetryAfter: time.Nanosecond}).Error())
}

func TestAttemptOutcomeZeroValueIsAFailure(t *testing.T) {
	t.Parallel()

	var outcome security.AttemptOutcome

	assert.Equal(t, security.AttemptFailed, outcome, "an outcome nobody set counts against the key")
	assert.NotEqual(t, security.AttemptSucceeded, security.AttemptInconclusive)
}

func TestErrorClassRanksTheThrottle(t *testing.T) {
	t.Parallel()

	throttled := &security.TooManyAttemptsError{RetryAfter: time.Second}
	refused := func(causes ...error) error {
		return fmt.Errorf("%w: %w", security.ErrAuthenticatorRefused, errors.Join(causes...))
	}

	cases := []struct {
		name string
		err  error
		want string
	}{
		{"sentinel", security.ErrTooManyAttempts, security.ErrorClassTooManyAttempts},
		{"wrapped", fmt.Errorf("basic: %w", throttled), security.ErrorClassTooManyAttempts},
		// A throttle is not a verdict: joined with another authenticator's
		// refusal it makes the client back off, not drop its credentials.
		{"before a verdict", refused(security.ErrInvalidCredentials, throttled), security.ErrorClassTooManyAttempts},
		{"before an absence of credentials", errors.Join(security.ErrUnsupportedCredential, throttled),
			security.ErrorClassTooManyAttempts},
		// An outage still comes first, and a malformed request before it.
		{"after an outage", errors.Join(throttled, security.ErrUnavailable), security.ErrorClassUnavailable},
		{"after a malformed request", errors.Join(throttled, security.ErrInvalidRequest), security.ErrorClassInvalidRequest},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, c.want, security.ErrorClass(c.err))
		})
	}
}

func TestParseClientAddr(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   string
		want netip.Addr
	}{
		{"203.0.113.7:51234", netip.MustParseAddr("203.0.113.7")},
		{"[2001:db8::1]:443", netip.MustParseAddr("2001:db8::1")},
		{"[::ffff:192.0.2.1]:80", netip.MustParseAddr("192.0.2.1")}, // unmapped
		{"[fe80::1%eth0]:80", netip.MustParseAddr("fe80::1")},       // zone dropped
		{"198.51.100.1", netip.MustParseAddr("198.51.100.1")},       // bare IP
		{"2001:db8::2", netip.MustParseAddr("2001:db8::2")},
		{"::ffff:10.0.0.1", netip.MustParseAddr("10.0.0.1")},
		{"", netip.Addr{}},
		{"bufconn", netip.Addr{}},
		{"@", netip.Addr{}}, // an unnamed Unix socket
		{"/run/app.sock", netip.Addr{}},
		{"example.com:443", netip.Addr{}}, // a name is not an address
		{"203.0.113.7:", netip.Addr{}},
		{"[2001:db8::1]", netip.Addr{}},
	}

	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			t.Parallel()

			got := security.ParseClientAddr(c.in)

			assert.Equal(t, c.want, got)
			assert.Empty(t, got.Zone())
			assert.False(t, got.Is4In6())
		})
	}
}

func TestClientAddrRoundTrip(t *testing.T) {
	t.Parallel()

	_, ok := security.ClientAddrFromContext(context.Background())
	assert.False(t, ok, "nothing stored")

	addr := netip.MustParseAddr("2001:db8::7")
	ctx := security.WithClientAddr(context.Background(), addr)

	got, ok := security.ClientAddrFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, addr, got)

	// The address an application stored is kept as given — the zero Addr
	// included: "unknown" is an answer, and the adapters do not replace it.
	got, ok = security.ClientAddrFromContext(security.WithClientAddr(ctx, netip.Addr{}))
	assert.True(t, ok)
	assert.False(t, got.IsValid())

	// An IPv4-mapped or zoned address is stored in its canonical form.
	got, _ = security.ClientAddrFromContext(security.WithClientAddr(ctx, netip.MustParseAddr("::ffff:192.0.2.9")))
	assert.Equal(t, netip.MustParseAddr("192.0.2.9"), got)

	got, _ = security.ClientAddrFromContext(security.WithClientAddr(ctx, netip.MustParseAddr("fe80::9%lo0")))
	assert.Equal(t, netip.MustParseAddr("fe80::9"), got)
}

func TestAttemptKeyPrintsNoSubject(t *testing.T) {
	t.Parallel()

	key := security.AttemptKey{Realm: "basic", Subject: "Secret-typed-as-user", Source: netip.MustParseAddr("192.0.2.1")}
	nested := struct{ Key any }{key}

	// The subject may be a password typed in the username field: the key
	// renders its realm and source only, with every verb, slog handler and
	// encoding/json.
	var outs []string

	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
		outs = append(outs, fmt.Sprintf(verb, key), fmt.Sprintf(verb, nested))
	}

	var text, js bytes.Buffer

	slog.New(slog.NewTextHandler(&text, nil)).Info("m", "key", key, "nested", nested)
	slog.New(slog.NewJSONHandler(&js, nil)).Info("m", "key", key, "nested", nested)

	encoded, err := json.Marshal(nested)
	require.NoError(t, err)

	outs = append(outs, text.String(), js.String(), string(encoded))

	for _, out := range outs {
		assert.NotContains(t, out, "Secret-typed-as-user")
	}

	assert.Equal(t, `security.AttemptKey{Realm: "basic", Subject: REDACTED, Source: 192.0.2.1}`, key.String())
	assert.Equal(t, `security.AttemptKey{Realm: "", Subject: "", Source: invalid IP}`, security.AttemptKey{}.String())
	assert.Contains(t, js.String(), `"key":{"realm":"basic","source":"192.0.2.1"}`)
	assert.Equal(t, `{"Key":{"Realm":"basic","Subject":"REDACTED","Source":"192.0.2.1"}}`, string(encoded))
}

func TestRetryAfterSeconds(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   time.Duration
		want int64
	}{
		{-time.Second, 0},
		{0, 0},
		{time.Nanosecond, 1},
		{time.Second, 1},
		{time.Second + time.Nanosecond, 2},
		{2 * time.Second, 2},
		{90 * time.Minute, 5400},
		{math.MaxInt64, math.MaxInt64/int64(time.Second) + 1},
	}

	for _, c := range cases {
		assert.Equal(t, c.want, security.RetryAfterSeconds(c.in), c.in.String())
	}
}
