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
//   - the errors behind an answer that cannot carry them: every storage
//     failure at /revoke, reported as a server_error — when it leaves the
//     revocation unfinished, /revoke answers a bare 503
//     temporarily_unavailable (RFC 7009 §2.2.1) that is not reported
//     again — a failed token lookup at /introspect, or an
//     [IntrospectionPolicy] that failed (the token is withheld behind a
//     bare {"active":false}, RFC 7662 §2.1, §2.2), and a [ClientStore]
//     that failed (a server_error carrying its error, whatever the
//     endpoint answers: 500, or 503 at /revoke).
//
// A failed client authentication at /token, /revoke or /introspect reaches
// it as the invalid_client the wire carries — "client authentication
// failed", whatever the reason — whose cause holds the refusal it replaced:
// errors.As on its Unwrap finds the detailed [*Error] ("unknown client",
// "method not allowed for client"…), and errors.Is finds
// [ErrClientNotAtIssuer] for a client of another issuer.
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
