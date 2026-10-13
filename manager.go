// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security

import (
	"context"
	"errors"
	"fmt"
)

// Manager orchestrates a chain of [Authenticator]s with first-success-wins
// semantics:
//
//   - Authenticators are consulted in registration order.
//   - Each authenticator whose Supports() returns true is invoked.
//   - On success — an authenticated value and no error — the result is
//     returned immediately; subsequent authenticators are NOT consulted.
//   - An error whose [ErrorClass] is [ErrorClassUnsupportedCredential] — it
//     wraps [ErrUnsupportedCredential] and no higher-ranked sentinel — is a
//     runtime bail-out: the authenticator abstains, as if Supports had
//     returned false.
//   - Any other error, and a success without an authenticated value (nil,
//     a typed nil or an unauthenticated value: a contract violation), is a
//     refusal: the next supporting authenticator is tried. If every one refuses, the refusals are joined and wrapped in
//     [ErrAuthenticatorRefused].
//   - If no authenticator supports the credential (or all bail out),
//     [ErrUnsupportedCredential] is returned: the transports answer it like
//     a request without credentials (HTTP 401 without error code).
//
// On failure the returned Authentication is [Anonymous]: the presented
// credentials never flow back to the caller.
//
// Manager is safe for concurrent use.
type Manager interface {
	Authenticate(ctx context.Context, auth Authentication) (Authentication, error)
}

// NewManager returns a [Manager] consulting the given authenticators in
// order. Passing zero authenticators is allowed; the returned manager will
// always return [ErrUnsupportedCredential]. NewManager panics if one of the
// authenticators is nil.
func NewManager(authenticators ...Authenticator) Manager {
	for i, a := range authenticators {
		if a == nil {
			panic(fmt.Sprintf("security: NewManager: nil Authenticator at index %d", i))
		}
	}

	cp := make([]Authenticator, len(authenticators))
	copy(cp, authenticators)

	return &manager{authenticators: cp}
}

type manager struct {
	authenticators []Authenticator
}

// Authenticate implements [Manager].
func (m *manager) Authenticate(ctx context.Context, auth Authentication) (Authentication, error) {
	ctx, span := tracer().Start(ctx, "security.Manager.Authenticate")
	defer span.End()

	span.SetAttributes(AttrAuthenticatorsCount.Int(len(m.authenticators)))

	var refusals []error

	for _, a := range m.authenticators {
		if !a.Supports(auth) {
			continue
		}

		name := authenticatorName(a)
		span.AddEvent("authenticator.try", trAttrName(name))

		result, err := a.Authenticate(ctx, auth)
		if err == nil {
			err = requireAuthenticated(result, "authenticator "+name)
		}

		if err == nil {
			span.SetAttributes(
				AttrAuthenticated.Bool(true),
				AttrAuthenticatorName.String(name),
			)

			return result, nil
		}

		if ErrorClass(err) == ErrorClassUnsupportedCredential {
			// Runtime bail-out: the authenticator abstains. An error that
			// also wraps a verdict or an outage is that verdict or outage.
			continue
		}

		refusals = append(refusals, fmt.Errorf("%s: %w", name, err))
	}

	if len(refusals) == 0 {
		recordFailure(span, ErrUnsupportedCredential)

		return Anonymous(), ErrUnsupportedCredential
	}

	err := fmt.Errorf("%w: %w", ErrAuthenticatorRefused, errors.Join(refusals...))
	recordFailure(span, err)

	return Anonymous(), err
}

// authenticatorName returns the [NamedAuthenticator] name if implemented, or
// the Go type name as a fallback.
func authenticatorName(a Authenticator) string {
	if n, ok := a.(NamedAuthenticator); ok {
		return n.AuthenticatorName()
	}

	return fmt.Sprintf("%T", a)
}
