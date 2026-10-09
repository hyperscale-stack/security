// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"context"
	"time"
)

// TokenKind tells apart the two kinds of token /introspect resolves. The
// values are the RFC 7009 §4.1.2 token type hints.
type TokenKind string

const (
	// TokenKindAccess is an access token.
	TokenKindAccess TokenKind = "access_token"
	// TokenKindRefresh is a refresh token.
	TokenKindRefresh TokenKind = "refresh_token"
)

// IntrospectedToken describes an active token to an [IntrospectionPolicy]
// before anything is disclosed: the claims the /introspect response would
// carry, never the token value or its hash.
type IntrospectedToken struct {
	// Kind tells an access token from a refresh token.
	Kind TokenKind
	// ClientID is the client the token was issued to — usually not the
	// caller, which is the resource server asking.
	ClientID string
	// Subject is the resource owner, or the client itself for a
	// client_credentials token.
	Subject string
	// Scope is the space-delimited scope granted to the token.
	Scope string
	// Audience is the aud claim of an access token. It is always empty for
	// a refresh token, and empty for an access token when the
	// IssuerResolver returned no audience.
	Audience string
	// IssuedAt is the issuance time.
	IssuedAt time.Time
	// ExpiresAt is the expiry time.
	ExpiresAt time.Time
}

// IntrospectionPolicy decides whether the caller of /introspect may learn
// the metadata of an active token: the RFC 7662 §2.2 "not allowed to
// introspect this particular token" check, and the place to enforce
// resource and tenant boundaries. RFC 7662 §4 says protected resources
// SHOULD be specifically authorized, and makes the check mandatory for a
// token that can be used only at certain resource servers: the
// authorization server MUST then determine whether it can be used at the
// resource server making the call.
//
// The result decides the response:
//
//   - (true, nil) discloses the token: "active":true plus its claims.
//   - (false, nil) withholds it: a bare {"active":false}, the very bytes an
//     unknown token gets. A denial is an expected outcome, not reported to
//     the [ErrorHook].
//   - (_, err) fails closed: the token is withheld the same way, whatever
//     the bool, and err reaches the [ErrorHook] as a server_error
//     ("introspection policy failed"). Set [ServerConfig.OnError] along with
//     a policy, or its failures go unseen.
//
// The policy only runs for an active token — an unknown, expired or
// consumed one answers {"active":false} without consulting it — and only
// once the caller has authenticated, so caller.Type() is always
// [ClientConfidential]. caller is the client the authentication returned —
// the [ClientStore] record for the built-in methods — so it can be
// type-asserted to your own [Client] implementation to read tenant
// metadata. ctx is the request context; request-derived data, such as a
// tenant resolved from the Host header, must be put there by middleware.
//
// Do not reduce the check to caller.ID() == token.ClientID: the resource
// server introspecting a token is usually not the client it was issued to.
// Refresh tokens carry no audience and are meant for their client alone:
// refuse them to resource servers.
//
// The policy runs synchronously on the request goroutine, before any byte
// of the response is written, and may be called concurrently. It MUST NOT
// panic: return an error to fail closed. A withheld token is
// indistinguishable from an unknown one on the wire only — the response
// time may differ.
type IntrospectionPolicy func(ctx context.Context, caller Client, token IntrospectedToken) (bool, error)
