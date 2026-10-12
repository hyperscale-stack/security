// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hyperscale-stack/security/oauth2/internal/scopes"
)

// MaxExtensionDataLength is the longest ExtensionGrant.Data, in bytes, an
// authorization records: the whole per-grant budget of an [Extension] —
// the authentication event, the claims requested, its own markers — copied
// onto the code and onto every token issued from it.
const MaxExtensionDataLength = 4096

// ErrUnredirectableRequest marks an /authorize refusal that MUST NOT be
// redirected — e.g. an OpenID Connect request without the redirect_uri it
// requires: the error response would travel to a redirection URI the
// client did not name (RFC 6749 §4.1.2.1). Returned, or wrapped with %w,
// by an [Extension] authorization hook, it makes the handler answer a
// bare 400 Bad Request itself; the cause reaches the [ErrorHook] only. A
// ConsentFunc writes its own response instead.
var ErrUnredirectableRequest = errors.New("oauth2: authorization request refused without redirect")

// ErrAuthorizeRequestModified is the cause of the server_error answering an
// /authorize request whose [AuthorizeRequest] a callback modified — a
// [ConsentFunc] or an [Extension] hook, changing any field of its copy but
// ExtensionRequest, or the identity of the client it shares with the
// server. The request is read-only: a consent narrows the grant through
// Consent.Scope, an extension through ExtensionGrant.Scope. Failing closed
// keeps a callback that relied on rewriting the request from silently
// granting what it meant to refuse. Match it with errors.Is in the
// [ErrorHook]; it never reaches the client.
var ErrAuthorizeRequestModified = errors.New("oauth2: a callback modified the authorization request it was handed")

// Extension is an optional protocol extension of the authorization-code
// flow, registered on [ServerConfig.Extension] — an OpenID Connect
// provider is the reference use: it validates its own authorization
// parameters, turns the application's trusted authentication result into
// the context the grant records, and adds an id_token to the token
// response, without a second /token endpoint.
//
// The server keeps every OAuth 2.0 check and runs it first: an extension
// only sees requests and exchanges the core accepted, can only narrow a
// granted scope, and can only add members RFC 6749 §5.1 does not define to
// a token response — access_token, token_type, expires_in, refresh_token
// and scope stay the server's.
//
// The context an extension records (ExtensionGrant.Data) is persisted with
// the authorization code and copied verbatim onto every token issued from
// it, through every refresh-token rotation: it is bound to the client, the
// issuer, the redirect URI and the token family of its grant, and the
// stores refuse a rotation that would change it. An extension reads it back
// in ExtendTokenResponse, and a consumer serving end-user data (a UserInfo
// endpoint) from [AccessToken.ExtensionData] — which is empty for tokens no
// authorization precedes (client_credentials, password) and for records
// written before it existed: such a consumer MUST require its own context,
// and an [AccessToken.Issuer] equal to the issuer it serves.
//
// Errors: an error that is, or wraps, an [*Error] whose code the
// authorization endpoint defines (RFC 6749 §4.1.2.1, OpenID Connect Core
// §3.1.2.6) is redirected to the client by the authorization hooks — its
// description and error_uri only when they fit the RFC 6749 charset;
// [ErrUnredirectableRequest] is answered with a bare 400; anything else is
// a server_error whose cause reaches the [ErrorHook] only. At /token, an
// invalid_grant [*Error] is answered as is and anything else is a
// server_error.
//
// Implementations MUST be safe for concurrent use, MUST NOT panic, and
// MUST NOT log or persist the requests and tokens they are handed: an
// /authorize request posted by a login form carries credentials in r.Form,
// and TokenIssuance.Access carries the raw access token.
type Extension interface {
	// ValidateAuthorizeRequest validates the extension's own parameters of
	// an /authorize request the core validated — client, redirect URI,
	// response mode and type, scope, PKCE — and whose issuer is resolved
	// (ar.Issuer). It runs on every /authorize call, before the
	// ConsentFunc, which gets its result as AuthorizeRequest.ExtensionRequest
	// (nil: nothing to add, e.g. a request outside the extension's
	// protocol). ar is a read-only copy: changing it fails the request with
	// server_error ([ErrAuthorizeRequestModified]). r is the request as
	// received: the core refused it when it repeats a parameter the core
	// reads, but r.Form still holds the empty occurrences — which RFC 6749
	// §3.1 omits: read the core's parameters from ar, never r.FormValue,
	// which an empty occurrence can hide them from — the extension's own
	// parameters as sent, repeated or not (refuse your own repetitions), and
	// the nonce unbounded: bound it.
	ValidateAuthorizeRequest(ctx context.Context, r *http.Request, ar *AuthorizeRequest) (any, error)

	// CompleteAuthorization decides what an approved authorization records.
	// It validates the trusted result the ConsentFunc returned
	// (consent.ExtensionResult) against the request — the authentication
	// event MUST be the one of consent.Subject, within the realm of
	// ar.Issuer, and a result the extension did not define MUST be
	// refused — and returns the [ExtensionGrant] the code, or the implicit
	// access token, records. consent.Scope is the granted scope, the
	// consent's narrowing applied; now is the server clock reading the code
	// is stamped with. ar is a read-only copy — changing it fails the
	// request with server_error ([ErrAuthorizeRequestModified]) — and
	// consent a copy; the values they carry (Client, ExtensionRequest,
	// ExtensionResult) are shared and MUST NOT be mutated. It MUST NOT have
	// externally visible side effects: the authorization can still fail
	// after it returns.
	CompleteAuthorization(ctx context.Context, ar *AuthorizeRequest, consent Consent, now time.Time) (ExtensionGrant, error)

	// ExtendTokenResponse adds members to the response of an
	// authorization_code or refresh_token exchange whose tokens are minted
	// but not yet persisted: when it fails, nothing is persisted — a
	// redeemed code stays consumed, a presented refresh token stays usable —
	// and what it returns is dropped when the persistence fails afterwards.
	// It MUST NOT have externally visible side effects for the same reason.
	// The client_credentials and password grants, and the implicit flow,
	// never call it.
	ExtendTokenResponse(ctx context.Context, issuance TokenIssuance) (TokenResponseExtension, error)
}

// ExtensionGrant is an [Extension]'s decision on an approved authorization.
type ExtensionGrant struct {
	// Scope, when it holds a scope token, narrows the granted scope — e.g.
	// dropping an offline_access the extension must ignore (OpenID Connect
	// Core §11). It is parsed like a request's scope — SP-separated RFC 6749
	// §3.3 tokens, at most 100 and 4096 bytes, duplicates dropped — and each
	// token MUST be granted already: a malformed or broader one fails the
	// request with server_error. A blank Scope — empty or SPs only — keeps
	// the consented one.
	Scope string
	// Data is the opaque, extension-defined grant context recorded as
	// ExtensionData on the code, or implicit access token, and on every
	// token issued from it, unchanged across refreshes (OpenID Connect Core
	// §12.2, RFC 9068 §2.2.1). At most [MaxExtensionDataLength] bytes of
	// valid UTF-8 without NUL — anything else fails the request with
	// server_error, so every store keeps it byte-exact.
	Data string
}

// TokenIssuance describes, to [Extension.ExtendTokenResponse], an exchange
// whose tokens are minted but not yet persisted.
type TokenIssuance struct {
	// GrantType is GrantTypeAuthorizationCode or GrantTypeRefreshToken.
	GrantType string
	// Client is the client authenticated at /token, the one the grant is
	// bound to.
	Client Client
	// Access is a copy of the access token about to be persisted: the raw
	// Token (OpenID Connect Core §3.1.3.6 at_hash), its Subject, Scope,
	// Audience, IssuedAt and ExpiresAt, and the Issuer and ExtensionData of
	// the grant — bound to the redeemed code or refresh token.
	Access AccessToken
	// Nonce is the nonce the authorization code recorded: set at the code
	// exchange only, always empty on a refresh (OpenID Connect Core §12.2).
	// The core does not bound it: an extension bounds it when it validates
	// the authorization request.
	Nonce string
	// RefreshTokenIssued reports whether a refresh token is persisted with
	// the access token — minted at a code exchange (a RefreshTokens
	// generator configured, and grant.Config.RefreshTokenScope satisfied),
	// or the replacement of a rotating refresh. It is false for a refresh
	// that does not rotate, whose presented token stays in use. An OpenID
	// provider fails closed on a refresh token the end-user did not consent
	// to (offline_access, OpenID Connect Core §11).
	RefreshTokenIssued bool
}

// TokenResponseExtension holds the members an [Extension] adds to a
// successful token response. It only has members RFC 6749 §5.1 does not
// define: an extension can never replace access_token, token_type,
// expires_in, refresh_token or scope.
type TokenResponseExtension struct {
	// IDToken is serialized as the id_token member (OpenID Connect Core
	// §3.1.3.3) when non-empty.
	IDToken string
}

// Why the server refuses what an [Extension] decided. They are the causes
// the ErrorHook gets; the client gets a bare server_error.
var (
	errExtensionScope = errors.New("oauth2: extension broadened the granted scope")
	errExtensionData  = errors.New("oauth2: extension data longer than MaxExtensionDataLength bytes, not UTF-8, or holding NUL")
)

// applyExtensionGrant returns the scope an authorization granting granted
// records once g applies, or why g cannot apply.
func applyExtensionGrant(granted string, g ExtensionGrant) (string, *Error) {
	if len(g.Data) > MaxExtensionDataLength || !utf8.ValidString(g.Data) || strings.IndexByte(g.Data, 0) >= 0 {
		return "", ErrServerError.WithCause(errExtensionData)
	}

	tokens, err := scopes.Parse(g.Scope)
	if err != nil {
		return "", ErrServerError.WithCause(errors.Join(errExtensionScope, err))
	}

	if len(tokens) == 0 {
		return granted, nil
	}

	if !scopes.NewSet(strings.Fields(granted)).Admits(tokens) {
		return "", ErrServerError.WithCause(errExtensionScope)
	}

	return scopes.Join(tokens), nil
}
