// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session

import (
	"context"

	"github.com/hyperscale-stack/security"
)

// Extractor implements [security.Extractor] for the cookie-session scheme.
// It reads the session cookie via the [Manager], decodes it, and returns a
// pending [Authentication]. Validation (expiry, principal resolution) is
// the [Authenticator]'s job.
type Extractor struct {
	mgr *Manager
}

// NewExtractor returns an [Extractor] bound to mgr.
func NewExtractor(mgr *Manager) Extractor { return Extractor{mgr: mgr} }

// Extract implements [security.Extractor]. Returns (nil, nil) when the
// request carries no decodable session cookie, so the engine moves on to
// the next extractor / anonymous flow.
func (e Extractor) Extract(ctx context.Context, c security.Carrier) (security.Authentication, error) {
	s, err := e.mgr.Get(ctx, c)
	if err != nil {
		// ErrNoSession and expiry both mean "no usable session here" —
		// the engine treats a nil result as "extractor did not apply".
		return nil, nil //nolint:nilerr // absent/expired session is not an extraction error
	}

	return newPending(s), nil
}
