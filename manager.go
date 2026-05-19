// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security

import (
	"context"
	"errors"
	"fmt"

	"go.opentelemetry.io/otel/codes"
)

// Manager orchestrates a chain of [Authenticator]s with first-success-wins
// semantics:
//
//   - Authenticators are consulted in registration order.
//   - The first authenticator whose Supports() returns true is invoked.
//   - On success, the resulting Authentication is returned immediately;
//     subsequent authenticators are NOT consulted.
//   - On error, the next supporting authenticator is tried; if every one
//     fails, the joined error is wrapped in [ErrAuthenticatorRefused].
//   - If no authenticator supports the credential, [ErrUnsupportedCredential]
//     is returned. The [Engine] then surfaces it as a 400 in the HTTP adapter.
//
// Manager is safe for concurrent use.
type Manager interface {
	Authenticate(ctx context.Context, auth Authentication) (Authentication, error)
}

// NewManager returns a [Manager] consulting the given authenticators in
// order. Passing zero authenticators is allowed; the returned manager will
// always return [ErrUnsupportedCredential].
func NewManager(authenticators ...Authenticator) Manager {
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

	var (
		anySupported bool
		errs         []error
	)

	for _, a := range m.authenticators {
		if !a.Supports(auth) {
			continue
		}

		anySupported = true
		name := authenticatorName(a)
		span.AddEvent("authenticator.try", trAttrName(name))

		result, err := a.Authenticate(ctx, auth)
		if err == nil {
			span.SetAttributes(
				AttrAuthenticated.Bool(true),
				AttrAuthenticatorName.String(name),
			)

			return result, nil
		}

		errs = append(errs, fmt.Errorf("%s: %w", name, err))
	}

	if !anySupported {
		err := ErrUnsupportedCredential
		span.SetStatus(codes.Error, err.Error())
		span.RecordError(err)

		return auth, err
	}

	joined := errors.Join(errs...)
	err := fmt.Errorf("%w: %w", ErrAuthenticatorRefused, joined)
	span.SetStatus(codes.Error, ErrAuthenticatorRefused.Error())
	span.RecordError(err)

	return auth, err
}

// authenticatorName returns the [NamedAuthenticator] name if implemented, or
// the Go type name as a fallback.
func authenticatorName(a Authenticator) string {
	if n, ok := a.(NamedAuthenticator); ok {
		return n.AuthenticatorName()
	}

	return fmt.Sprintf("%T", a)
}
