// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security

import "context"

// Extractor pulls raw, unauthenticated credentials from a [Carrier] and
// returns an [Authentication] that captures them. The returned value MUST
// have IsAuthenticated() == false: validation is the [Authenticator]'s job.
//
// Sentinel conventions:
//
//   - Return (nil, nil) when no credentials of the supported scheme are
//     present. The Engine treats this as "this extractor does not apply"
//     and consults the next one.
//   - Return (nil, err) wrapping a security sentinel when credentials were
//     present but malformed (e.g. invalid base64 in Basic). The Engine
//     surfaces err to the caller and stops; downstream authenticators are
//     not invoked.
//
// Implementations MUST be safe for concurrent use.
type Extractor interface {
	Extract(ctx context.Context, c Carrier) (Authentication, error)
}
