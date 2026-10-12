// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider

import "errors"

var (
	// ErrUnknownSubject is what a [ClaimsSource] returns — wrapped with %w,
	// or as is — for an end-user that no longer exists or may no longer sign
	// in. The provider then refuses every exchange of the grant: the code
	// exchange and every refresh answer invalid_grant, UserInfo answers
	// invalid_token. It is the account-validity check of the provider: an
	// application disabling an end-user makes its source answer it.
	ErrUnknownSubject = errors.New("oidcprovider: unknown or disabled subject")

	// ErrInvalidKeyRing reports a [KeyRing] the provider refuses to sign
	// with or publish (see [KeyRing.Validate]). Every endpoint needing the
	// keys fails closed: server_error at /authorize and /token, 500 at the
	// JWK Set and discovery endpoints.
	ErrInvalidKeyRing = errors.New("oidcprovider: invalid key ring")

	// ErrInvalidIssuer reports an issuer identifier that is not an https URL
	// with a host and without query, fragment or user info, in canonical
	// form (OpenID Connect Core §2, Discovery §3) — or an http URL without
	// [Config.AllowInsecureLoopbackIssuer] and a loopback host.
	ErrInvalidIssuer = errors.New("oidcprovider: invalid issuer identifier")
)
