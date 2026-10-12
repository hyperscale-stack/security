// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package grant ships the grant-type handlers consumed by the OAuth2
// server's /token endpoint. Each handler satisfies [oauth2.Grant] and is
// registered in the server's grant table at construction time.
//
// Three grants are shipped:
//
//   - authorization_code (with PKCE; PKCE is mandatory in
//     [oauth2.Profile20BCP] and [oauth2.Profile21Draft] and, under every
//     profile, for every client that is not confidential); a replayed code
//     revokes the tokens it issued
//   - client_credentials, for confidential clients only
//   - refresh_token (rotation + reuse detection; rotation is mandatory in
//     [oauth2.Profile20BCP] and [oauth2.Profile21Draft] and, under every
//     profile, for every client that is not confidential)
//
// Legacy grants (password, implicit) live behind explicit opt-in helpers
// and are refused outside [oauth2.Profile20].
package grant

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/token"
)

// Config gathers the runtime knobs every grant needs.
type Config struct {
	// Storage is the persistence layer.
	Storage oauth2.Storage
	// AccessTokens issues access tokens (opaque or JWT).
	AccessTokens token.AccessTokenGenerator
	// RefreshTokens issues refresh tokens. Optional for authorization_code
	// and password, which emit no refresh token without it — nor to a client
	// not declaring the refresh_token grant, nor for a grant missing
	// RefreshTokenScope, when that is set. Required by
	// refresh_token whenever it rotates — always under
	// [oauth2.Profile20BCP] and [oauth2.Profile21Draft] — since the
	// replacement is minted with it; see [ErrRotationRequiresGenerator].
	RefreshTokens token.RefreshTokenGenerator
	// AccessTTL is the access-token expiry window.
	AccessTTL time.Duration
	// RefreshTTL is the refresh-token expiry window. Honored when
	// RefreshTokens is non-nil.
	RefreshTTL time.Duration
	// RefreshFamilyTTL, when positive, bounds the lifetime of a
	// refresh-token family — every refresh token derived from one
	// authorization — counted from its first issuance
	// ([oauth2.RefreshToken.FamilyIssuedAt]): a refresh after that is
	// refused with invalid_grant, nothing consumed, and no refresh token is
	// minted expiring later. RefreshTTL keeps expiring a token its client
	// leaves unused — the inactivity expiry RFC 9700 §4.14.2 recommends;
	// this absolute bound also ends a family a thief keeps alive by
	// rotating it. Zero, the default, sets no bound. It applies to existing
	// families as soon as it is set: every family records its start.
	// Access tokens are not capped: they live AccessTTL.
	RefreshFamilyTTL time.Duration
	// RefreshTokenScope, when set, makes the authorization_code and legacy
	// password grants issue a refresh token only when the granted scope
	// holds this exact scope token — e.g. "offline_access", the consent
	// OpenID Connect Core §11 requires before a refresh token enabling
	// offline access is returned. Empty, the default, issues one whenever
	// RefreshTokens is set. A refresh_token exchange keeps rotating the
	// token it is presented: the replacement keeps that token's scope (RFC
	// 6749 §6), so the rule governs the grants authorized after it is set.
	RefreshTokenScope string
	// RequirePKCE forces PKCE on authorization_code for confidential
	// clients too. Every other client — public or untyped — needs PKCE under
	// every profile (RFC 9700 §2.1.1), and [oauth2.Profile20BCP] and
	// [oauth2.Profile21Draft] require it of every client, whatever this
	// field says.
	RequirePKCE bool
	// RotateRefreshTokens makes refresh_token issue a fresh refresh token
	// on every exchange and atomically mark the presented one consumed;
	// replaying a consumed token revokes the whole family (RFC 9700
	// §4.14.2). [oauth2.Profile20BCP] and [oauth2.Profile21Draft] mandate
	// rotation whatever this field says, and the refresh tokens of a client
	// that is not confidential rotate under every profile (RFC 9700
	// §4.14.2), so it only matters for confidential clients under
	// [oauth2.Profile20], where false keeps the legacy behavior: the
	// refresh token stays reusable until it expires. Rotation requires
	// RefreshTokens.
	RotateRefreshTokens bool
	// OnError, when set, observes the errors a grant swallows to keep the
	// protocol response intact — today, a family revocation that failed
	// after a refresh-token reuse, whether the grant found the token
	// consumed or the store reported the reuse while rotating, or after an
	// authorization-code replay (RFC 6749 §4.1.2): exactly one server_error
	// per failed revocation, whose cause matches
	// [oauth2.ErrTokenFamilyRevocationFailed] with a conforming store.
	// Errors returned to the server travel to [oauth2.ServerConfig.OnError]
	// instead, so wire both to the same sink. Optional; see
	// [oauth2.ErrorHook].
	OnError oauth2.ErrorHook
}

// issuesRefreshFor reports whether an exchange by client granting scope
// gets a refresh token: the config carries a generator, the client declares
// the refresh_token grant — RFC 9700 §4.14.2: the server decides which
// clients get refresh tokens — and, when RefreshTokenScope is set, scope
// holds it.
func (c Config) issuesRefreshFor(client oauth2.Client, scope string) bool {
	if c.RefreshTokens == nil || !oauth2.ClientAllowsGrantType(client, oauth2.GrantTypeRefreshToken) {
		return false
	}

	return c.RefreshTokenScope == "" || slices.Contains(strings.Fields(scope), c.RefreshTokenScope)
}

// refreshExpiry is the expiry of a refresh token minted at now into a
// family started at start: RefreshTTL after now, never past the family's
// deadline when RefreshFamilyTTL sets one.
func (c Config) refreshExpiry(now, start time.Time) time.Time {
	expires := now.Add(c.RefreshTTL)

	if c.RefreshFamilyTTL > 0 {
		if deadline := start.Add(c.RefreshFamilyTTL); expires.After(deadline) {
			return deadline
		}
	}

	return expires
}

// familyExpired reports whether a family started at start is past its
// deadline — RefreshFamilyTTL after start, when set — at now.
func (c Config) familyExpired(start, now time.Time) bool {
	return c.RefreshFamilyTTL > 0 && now.After(start.Add(c.RefreshFamilyTTL))
}

// checkGrantType returns nil when client declares grantType
// ([oauth2.ClientAllowsGrantType]), otherwise unauthorized_client (RFC 6749
// §5.2) — with [oauth2.ErrNoGrantTypesDeclared] as cause when client
// declares no grant type at all. The server checks it before a grant runs;
// the grants check it again for direct calls and decorators.
func checkGrantType(client oauth2.Client, grantType string) error {
	if oauth2.ClientAllowsGrantType(client, grantType) {
		return nil
	}

	refusal := oauth2.ErrUnauthorizedClient.WithDescription("client cannot use " + grantType)
	if len(client.GrantTypes()) == 0 {
		return refusal.WithCause(oauth2.ErrNoGrantTypesDeclared)
	}

	return refusal
}

// notifyError hands err to the configured [oauth2.ErrorHook], if any.
func (c Config) notifyError(ctx context.Context, err error) {
	if c.OnError == nil || err == nil {
		return
	}

	c.OnError(ctx, err)
}

// detachedRevocationTimeout bounds a family revocation detached from the
// request that triggered it.
const detachedRevocationTimeout = 10 * time.Second

// revokeFamilyDetached revokes familyID as the security response to a
// detected replay. It runs on a context detached from the request's
// cancellation — a client hanging up must not abort the revocation its
// replay triggered — bounded by detachedRevocationTimeout. The caller
// reports a failure: it cannot change the answer the client gets.
func (c Config) revokeFamilyDetached(ctx context.Context, familyID string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), detachedRevocationTimeout)
	defer cancel()

	return c.Storage.RevokeRefreshFamily(ctx, familyID) //nolint:wrapcheck // reported as the hook cause, unchanged
}

// Request and Response are type aliases anchoring the contract in the
// parent oauth2 package so handlers and the Server share one definition.
type (
	Request  = oauth2.GrantRequest
	Response = oauth2.GrantResponse
)
