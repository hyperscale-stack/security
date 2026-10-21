// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/hyperscale-stack/security/oauth2"
)

// maxHintLength bounds an id_token_hint, in bytes.
const maxHintLength = 16 << 10

// maxSubjectLength is the longest sub (OpenID Connect Core §2: 255 ASCII
// characters).
const maxSubjectLength = 255

// errInvalidHint answers an id_token_hint the provider did not issue to the
// requesting client; the hint never reaches the error, nor the hook's cause.
var errInvalidHint = oauth2.ErrInvalidRequest.WithDescription("the id_token_hint is not an ID Token of this provider for this client")

// errHintClaims is the cause of a refusal on the hint's claims.
var errHintClaims = errors.New("oidcprovider: id_token_hint claims")

// verifyHint returns the sub of id_token_hint raw — "" without one — once
// the provider has verified it issued it (Core §3.1.2.2: "the OP MUST
// validate that it was the issuer of the ID Token"): signed by one of the
// issuer's published keys with an ID Token algorithm, typed JWT or untyped
// (an at+jwt access token is no hint), iss the request issuer, the
// requesting client among its audiences (a hint is "about the End-User's
// current or past authenticated session with the Client", Core §3.1.2.1),
// a sub of at most 255 bytes. Its expiry is not checked: an expired ID
// Token is accepted (Core §3.1.2.2). A header carrying or locating a key —
// jwk, x5c, jku, x5u (Core §2: ID Tokens SHOULD NOT use them) — is refused
// by jwtsec.VerifySignature before go-jose parses it.
func (p *Provider) verifyHint(ctx context.Context, raw, issuer, clientID string, snap *keySnapshot) (string, error) {
	if raw == "" {
		return "", nil
	}

	if len(raw) > maxHintLength {
		return "", errInvalidHint
	}

	verified, err := jwtsec.VerifySignature(ctx, raw, snap.verification, idTokenAlgorithms...)
	if err != nil {
		return "", errInvalidHint.WithCause(err)
	}

	if verified.Type != "" && !isJWTType(verified.Type) {
		return "", errInvalidHint.WithCause(errHintClaims)
	}

	var claims map[string]json.RawMessage
	if err := json.Unmarshal(verified.Payload, &claims); err != nil {
		return "", errInvalidHint.WithCause(errHintClaims)
	}

	var iss, sub string

	aud := audience(claims[claimAud])

	switch {
	case json.Unmarshal(claims[claimIss], &iss) != nil || iss != issuer,
		json.Unmarshal(claims[claimSub], &sub) != nil || sub == "" || len(sub) > maxSubjectLength,
		!slices.Contains(aud, clientID):
		return "", errInvalidHint.WithCause(errHintClaims)
	}

	return sub, nil
}

// audience decodes an aud claim: a string or an array of strings (RFC 7519
// §4.1.3).
func audience(raw json.RawMessage) []string {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}
	}

	var many []string
	if json.Unmarshal(raw, &many) == nil {
		return many
	}

	return nil
}

// isJWTType reports whether typ is the JWT media type (RFC 7519 §5.1),
// compared as RFC 7515 §4.1.9 prescribes: case-insensitively, "application/"
// implied.
func isJWTType(typ string) bool {
	typ = strings.ToLower(typ)

	return typ == "jwt" || typ == "application/jwt"
}
