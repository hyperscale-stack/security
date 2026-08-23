// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import "context"

// ErrorHook observes the errors the authorization server would otherwise
// keep to itself:
//
//   - every error the server turns into an RFC 6749 §5.2 error response.
//     The hook receives the [*Error] envelope with its Cause intact, which
//     is the only place the cause of a server_error is ever exposed — the
//     wire response deliberately drops it.
//   - the errors the server swallows to stay protocol-compliant, such as a
//     best-effort revocation that failed (RFC 7009 §2.2 mandates 200 OK
//     whatever happened).
//
// The hook is a pure observability sink: it MUST NOT influence the
// response. It runs synchronously on the request goroutine, so a slow
// implementation slows the request down.
//
// Use [IsCode] to filter out the expected 4xx traffic, and errors.Unwrap /
// errors.As to reach the underlying cause:
//
//	OnError: func(ctx context.Context, err error) {
//		if oauth2.IsCode(err) != oauth2.CodeServerError {
//			return
//		}
//
//		slog.ErrorContext(ctx, "oauth2 server error", "err", err)
//	}
type ErrorHook func(ctx context.Context, err error)
