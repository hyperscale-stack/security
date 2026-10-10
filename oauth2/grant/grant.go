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
//     [oauth2.Profile20BCP] and [oauth2.Profile21Draft])
//   - client_credentials
//   - refresh_token (rotation + reuse detection; rotation is mandatory in
//     [oauth2.Profile20BCP] and [oauth2.Profile21Draft])
//
// Legacy grants (password, implicit) live behind explicit opt-in helpers
// and are refused outside [oauth2.Profile20].
package grant

import (
	"context"
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
	// and password, which emit no refresh token without it. Required by
	// refresh_token whenever it rotates — always under
	// [oauth2.Profile20BCP] and [oauth2.Profile21Draft] — since the
	// replacement is minted with it; see [ErrRotationRequiresGenerator].
	RefreshTokens token.RefreshTokenGenerator
	// AccessTTL is the access-token expiry window.
	AccessTTL time.Duration
	// RefreshTTL is the refresh-token expiry window. Honored when
	// RefreshTokens is non-nil.
	RefreshTTL time.Duration
	// RequirePKCE forces PKCE on authorization_code, independently of
	// public-vs-confidential client type. [oauth2.Profile20BCP] and
	// [oauth2.Profile21Draft] require PKCE whatever this field says.
	RequirePKCE bool
	// RotateRefreshTokens makes refresh_token issue a fresh refresh token
	// on every exchange and atomically mark the presented one consumed;
	// replaying a consumed token revokes the whole family (RFC 9700
	// §4.14.2). [oauth2.Profile20BCP] and [oauth2.Profile21Draft] mandate
	// rotation whatever this field says, so it only matters under
	// [oauth2.Profile20], where false keeps the legacy behavior: the
	// refresh token stays reusable until it expires. Rotation requires
	// RefreshTokens.
	RotateRefreshTokens bool
	// OnError, when set, observes the errors a grant swallows to keep the
	// protocol response intact — today, a family revocation that failed
	// after a refresh-token reuse, whether the grant found the token
	// consumed or the store reported the reuse while rotating: exactly one
	// server_error per failed revocation, whose cause matches
	// [oauth2.ErrTokenFamilyRevocationFailed] with a conforming store.
	// Errors returned to the server travel to [oauth2.ServerConfig.OnError]
	// instead, so wire both to the same sink. Optional; see
	// [oauth2.ErrorHook].
	OnError oauth2.ErrorHook
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
