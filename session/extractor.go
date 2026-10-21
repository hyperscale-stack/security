// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"errors"
	"fmt"

	"github.com/hyperscale-stack/security"
)

// Extractor implements [security.Extractor] for the cookie-session scheme.
// It reads the session cookie via the [Manager], decodes it, and returns a
// pending [Authentication]. Validation (expiry, principal resolution) is
// the [Authenticator]'s job.
type Extractor struct {
	mgr *Manager
}

// NewExtractor returns an [Extractor] bound to mgr. It panics on a nil
// Manager, which would fail on the first request.
func NewExtractor(mgr *Manager) Extractor {
	if mgr == nil {
		panic("session: NewExtractor: nil Manager")
	}

	return Extractor{mgr: mgr}
}

// Extract implements [security.Extractor]. Returns (nil, nil) when the
// request carries no usable session cookie — absent, undecodable, expired or
// refused by the Manager's validator — so the engine moves on to the next
// extractor / anonymous flow. A session that could not be checked (an error
// wrapping [security.ErrUnavailable] from the validator) is an error: the
// transports answer 503 rather than treating the user as signed out.
func (e Extractor) Extract(ctx context.Context, c security.Carrier) (security.Authentication, error) {
	s, err := e.mgr.Get(ctx, c)

	switch {
	case err == nil:
		return newPending(s), nil
	case errors.Is(err, security.ErrUnavailable):
		return nil, fmt.Errorf("session: %w", err)
	default:
		// ErrNoSession and expiry both mean "no usable session here" —
		// the engine treats a nil result as "extractor did not apply".
		return nil, nil //nolint:nilerr // absent/expired session is not an extraction error
	}
}
