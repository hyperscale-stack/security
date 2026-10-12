// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider

import (
	"fmt"

	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/hyperscale-stack/security/oauth2"
)

// IDTokenSigningClient is an optional capability of an oauth2.Client: the
// id_token_signed_response_alg it registered (OpenID Connect Dynamic
// Client Registration §2) — one of RS256, RS384, RS512, PS256, PS384,
// PS512, ES256, ES384, ES512. A client without it, or registering "",
// gets RS256 ID Tokens, the default. The issuer's key ring MUST hold a
// signing key of that algorithm: otherwise the client's OpenID requests
// answer server_error before any interaction.
type IDTokenSigningClient interface {
	IDTokenSignedResponseAlg() jwtsec.Algorithm
}

// signingKey returns the key the ID Tokens of client are signed with.
func signingKey(snap *keySnapshot, client oauth2.Client) (jwtsec.PrivateKey, error) {
	alg := jwtsec.RS256

	if c, ok := client.(IDTokenSigningClient); ok && c.IDTokenSignedResponseAlg() != "" {
		alg = c.IDTokenSignedResponseAlg()
	}

	key, ok := snap.signing[alg]
	if !ok {
		return jwtsec.PrivateKey{}, fmt.Errorf("oidcprovider: no %s signing key for the client's ID Tokens", alg)
	}

	return key, nil
}
