// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider

import "context"

// Scope values (OpenID Connect Core §3.1.2.1, §5.4, §11).
const (
	// ScopeOpenID makes an authorization request an OpenID Connect
	// authentication request (Core §3.1.2.1).
	ScopeOpenID = "openid"
	// ScopeProfile requests the default profile claims at UserInfo.
	ScopeProfile = "profile"
	// ScopeEmail requests email and email_verified at UserInfo.
	ScopeEmail = "email"
	// ScopeAddress requests address at UserInfo.
	ScopeAddress = "address"
	// ScopePhone requests phone_number and phone_number_verified at UserInfo.
	ScopePhone = "phone"
	// ScopeOfflineAccess requests a refresh token enabling access while the
	// end-user is absent (Core §11): wire grant.Config.RefreshTokenScope to
	// it, and grant it only with the end-user's consent
	// ([Decision].OfflineAccess).
	ScopeOfflineAccess = "offline_access"
)

// ClaimsSource supplies end-user claims. The provider asks it for the
// claims of an ID Token — at the code exchange and at every refresh — and
// of a UserInfo response, naming in [ClaimsQuery].Names the only claims it
// may release; whatever else the source returns is dropped, and so are
// null and empty-string values (Core §5.3.2) and the protocol claims the
// provider sets itself (sub, iss, aud, exp, iat, auth_time, nonce, acr,
// amr, at_hash, …) — a source cannot override them.
//
// The provider queries it on every token exchange of an OpenID grant, an
// ID Token being issued or not: returning [ErrUnknownSubject] for an
// end-user that no longer exists or may no longer sign in stops the grant
// (invalid_grant, invalid_token at UserInfo). Any other error answers
// server_error. Implementations MUST be safe for concurrent use.
type ClaimsSource interface {
	Claims(ctx context.Context, q ClaimsQuery) (map[string]any, error)
}

// ClaimsTarget tells where the claims of a [ClaimsQuery] go.
type ClaimsTarget string

const (
	// ClaimsForIDToken targets an ID Token — or, with no Names, only checks
	// that the end-user is still valid (a refresh issuing no ID Token).
	ClaimsForIDToken ClaimsTarget = "id_token"
	// ClaimsForUserInfo targets a UserInfo response.
	ClaimsForUserInfo ClaimsTarget = "userinfo"
)

// ClaimsQuery asks a [ClaimsSource] for the claims of one end-user.
type ClaimsQuery struct {
	// Issuer is the realm the end-user belongs to.
	Issuer string
	// Subject is the end-user's sub within Issuer.
	Subject string
	// ClientID is the client the claims are released to.
	ClientID string
	// Target is where the claims go.
	Target ClaimsTarget
	// Names lists the claims the provider may release: those of the granted
	// scopes (UserInfo) and those the end-user agreed to release through the
	// claims parameter. A language-tagged variant of a listed name
	// ("name#fr", Core §5.2) is released with it. Empty: release nothing.
	Names []string
}
