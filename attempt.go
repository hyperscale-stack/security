// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"time"
)

// AttemptLimiter limits the failed authentication attempts made against a
// key: the online-guessing control of NIST SP 800-63B-4 §3.2.2 and the
// brute-force protection RFC 6749 §2.3.1 and §4.3.2 require of OAuth 2.0
// endpoints that check a secret.
//
// A verifier calls Allow before it checks the credentials. When Allow
// admits the attempt, the verifier checks them, then calls Record exactly
// once with the same key and the outcome. When Allow returns an error, the
// verifier checks nothing and does not call Record.
//
// Allow reserves the attempt: it counts as failed until Record settles it,
// so concurrent attempts against one key never exceed its allowance — N
// guesses sent at once cannot all pass the check before the first failure
// is known. The price is that concurrent legitimate attempts hold
// reservations too: size the allowance above a client's concurrency, or
// authenticate once and carry a session or a token.
//
// Record returns no error on purpose: the charge was taken by Allow, so a
// Record that is lost errs toward limiting. Implementations MUST keep that
// property — counting failures in Record alone reopens the burst — and
// bound their own latency: Record is synchronous, and callers pass it a
// context that outlives a canceled request (context.WithoutCancel), since a
// failure must be recorded even when the client hung up.
//
// Implementations MUST be safe for concurrent use. The
// github.com/hyperscale-stack/security/throttle package ships a bounded,
// in-memory implementation; a deployment of several instances shares one
// over its own store.
type AttemptLimiter interface {
	// Allow admits or refuses one attempt against key, before the
	// credentials are checked. It returns nil to admit it, an error
	// wrapping ErrTooManyAttempts — a *TooManyAttemptsError — to refuse
	// it, or an error wrapping ErrUnavailable when it cannot decide. Any
	// non-nil error refuses the attempt; callers answer an error that wraps
	// neither sentinel as unavailable: they fail closed.
	Allow(ctx context.Context, key AttemptKey) error

	// Record settles an attempt Allow admitted, with its outcome.
	Record(ctx context.Context, key AttemptKey, outcome AttemptOutcome)
}

// AttemptKey names what an authentication attempt targets. Callers compose
// it from the credential type, the claimed identity and the client address;
// they never put a secret in it.
//
// Subject is chosen by the client — it may even be a password typed in the
// username field —, so an AttemptKey renders its subject REDACTED in fmt,
// slog and encoding/json output, and an implementation MUST NOT store it as
// given without a bound: it hashes it, as the throttle package does.
type AttemptKey struct {
	// Realm separates the allowances of credential types that share an
	// AttemptLimiter, such as "basic", "oauth2/client" or
	// "oauth2/password". Prefer one AttemptLimiter per credential type.
	Realm string

	// Subject is the identity the attempt claims — a username, a
	// client_id —, normalized by the caller so that every variant the
	// account store resolves to one account gives one value: variants
	// counted apart multiply the allowance. An empty Subject is a valid
	// key: the attempts that name no identity share one allowance.
	Subject string

	// Source is the address of the client the attempt comes from
	// ([ClientAddrFromContext]); the zero Addr when it is unknown.
	Source netip.Addr
}

// redacted replaces a subject that is set.
const redacted = "REDACTED"

// String implements fmt.Stringer with the realm and the source only: the
// subject is client input and prints REDACTED when it is set.
func (k AttemptKey) String() string {
	subject := `""`
	if k.Subject != "" {
		subject = redacted
	}

	return fmt.Sprintf("security.AttemptKey{Realm: %q, Subject: %s, Source: %s}", k.Realm, subject, k.Source)
}

// Format implements fmt.Formatter like String, for every verb, %#v
// included. fmt handles %p of a non-pointer value before any method: no
// type can redact that one.
func (k AttemptKey) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, k.String()) }

// LogValue implements slog.LogValuer with the realm and the source.
func (k AttemptKey) LogValue() slog.Value {
	return slog.GroupValue(slog.String("realm", k.Realm), slog.String("source", k.Source.String()))
}

// MarshalJSON encodes the key with its subject REDACTED when it is set.
func (k AttemptKey) MarshalJSON() ([]byte, error) {
	subject := ""
	if k.Subject != "" {
		subject = redacted
	}

	return json.Marshal(struct { //nolint:wrapcheck // strings only: never fails
		Realm   string
		Subject string
		Source  string
	}{k.Realm, subject, k.Source.String()})
}

// AttemptOutcome settles an attempt an [AttemptLimiter] admitted. The zero
// value is AttemptFailed: an attempt whose outcome nobody set counts
// against its key.
type AttemptOutcome uint8

// Outcomes of an authentication attempt.
const (
	// AttemptFailed: the credentials were checked and refused — a wrong
	// password, an unknown account, a disabled one.
	AttemptFailed AttemptOutcome = iota
	// AttemptSucceeded: the credentials were checked and accepted.
	AttemptSucceeded
	// AttemptInconclusive: the attempt ended without a verdict on the
	// credentials — a dependency was unavailable, the request ended before
	// the check. It does not count against the key.
	AttemptInconclusive
)

// TooManyAttemptsError is the refusal of an [AttemptLimiter]: errors.Is
// matches [ErrTooManyAttempts]. It is not a verdict on the credentials,
// which were not checked. The transports answer it with HTTP 429 Too Many
// Requests (RFC 6585 §4) and a Retry-After field, gRPC and Connect
// ResourceExhausted.
type TooManyAttemptsError struct {
	// RetryAfter is how long until the key gets its next attempt; zero
	// when the limiter does not know.
	RetryAfter time.Duration
}

// Error implements error with a fixed text and, when it is known, the
// delay rounded up to the second. It never names the key.
func (e *TooManyAttemptsError) Error() string {
	if e.RetryAfter <= 0 {
		return ErrTooManyAttempts.Error()
	}

	return fmt.Sprintf("%s (retry in %ds)", ErrTooManyAttempts.Error(), RetryAfterSeconds(e.RetryAfter))
}

// Unwrap returns [ErrTooManyAttempts].
func (e *TooManyAttemptsError) Unwrap() error { return ErrTooManyAttempts }

func (e *TooManyAttemptsError) securityError() {}

// RetryAfterSeconds returns d in whole seconds rounded up — the
// delay-seconds of an HTTP Retry-After field (RFC 9110 §10.2.3) —, at
// least 1 for a positive d and 0 otherwise.
func RetryAfterSeconds(d time.Duration) int64 {
	if d <= 0 {
		return 0
	}

	secs := d / time.Second
	if d%time.Second != 0 {
		secs++
	}

	return int64(secs)
}
