// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"strings"

	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/hyperscale-stack/security/oauth2"
)

// Why an exchange is refused on the server side: the causes the ErrorHook
// gets, the client a bare server_error.
var (
	errRefreshWithoutOffline = errors.New("oidcprovider: the grants issue a refresh token the end-user did not consent to (offline_access, Core §11)")
	errAudienceCollision     = errors.New("oidcprovider: the access token audience is the client ID, the ID Token audience")
	errClientMismatch        = errors.New("oidcprovider: the access token belongs to another client, or one not registered at its issuer")
)

// invalidGrant is the refusal of a grant the provider cannot honor any more.
func invalidGrant(description string, cause error) error {
	return oauth2.ErrInvalidGrant.WithDescription(description).WithCause(cause)
}

// extendTokenResponse adds the ID Token to the response of a code exchange
// or a refresh whose tokens are minted but not persisted. For every
// exchange of an OpenID grant it first applies the offline-access policy
// (Core §11) and checks the end-user is still valid — also when no ID
// Token comes out of it, the refreshed scope lacking openid.
func (p *Provider) extendTokenResponse(ctx context.Context, iss oauth2.TokenIssuance) (oauth2.TokenResponseExtension, error) {
	gc, present, err := decodeContext(iss.Access.ExtensionData)
	if err != nil {
		return oauth2.TokenResponseExtension{}, invalidGrant("the grant cannot be honored", err)
	}

	openID := hasScope(iss.Access.Scope, ScopeOpenID)

	if !present {
		// Core §3.1.3.2: a code redeemed for an ID Token must have been
		// issued for an OpenID request.
		if iss.GrantType == oauth2.GrantTypeAuthorizationCode && openID {
			return oauth2.TokenResponseExtension{}, invalidGrant("the code was not issued for an OpenID request", errContext)
		}

		return oauth2.TokenResponseExtension{}, nil
	}

	if err := p.offlinePolicy(gc, iss); err != nil {
		return oauth2.TokenResponseExtension{}, err
	}

	if iss.Client == nil || iss.Client.ID() != iss.Access.ClientID || !oauth2.ClientAllowsIssuer(iss.Client, iss.Access.Issuer) {
		return oauth2.TokenResponseExtension{}, errClientMismatch
	}

	var allowed map[string][]json.RawMessage
	if openID {
		allowed = p.names.releaseSet(gc.IDToken, nil)
	}

	claims, err := p.cfg.Claims.Claims(ctx, ClaimsQuery{
		Issuer: iss.Access.Issuer, Subject: iss.Access.Subject, ClientID: iss.Access.ClientID,
		Target: ClaimsForIDToken, Names: queryNames(allowed),
	})
	if err != nil {
		return oauth2.TokenResponseExtension{}, sourceFailure(err, func(e error) error {
			return invalidGrant("the end-user is unknown or disabled", e)
		})
	}

	if !openID {
		return oauth2.TokenResponseExtension{}, nil
	}

	released, err := releaseClaims(claims, allowed)
	if err != nil {
		return oauth2.TokenResponseExtension{}, err
	}

	idToken, err := p.signIDToken(ctx, iss, gc, released)
	if err != nil {
		return oauth2.TokenResponseExtension{}, err
	}

	return oauth2.TokenResponseExtension{IDToken: idToken}, nil
}

// sourceFailure maps a ClaimsSource error: ErrUnknownSubject through
// unknown, anything else to an internal failure.
func sourceFailure(err error, unknown func(error) error) error {
	if errors.Is(err, ErrUnknownSubject) {
		return unknown(err)
	}

	return fmt.Errorf("oidcprovider: claims source: %w", err)
}

// offlinePolicy refuses a refresh token the end-user did not consent to
// (Core §11) unless Config.AllowRefreshWithoutOfflineAccess: a code
// exchange minting one is a misconfiguration (server_error), and a refresh
// of such a grant is refused (invalid_grant: the client must authenticate
// the end-user again).
func (p *Provider) offlinePolicy(gc grantContext, iss oauth2.TokenIssuance) error {
	if gc.Offline || p.cfg.AllowRefreshWithoutOfflineAccess {
		return nil
	}

	if iss.GrantType == oauth2.GrantTypeRefreshToken {
		return invalidGrant("the grant does not allow offline access", errRefreshWithoutOffline)
	}

	if iss.RefreshTokenIssued {
		return errRefreshWithoutOffline
	}

	return nil
}

// signIDToken builds and signs the ID Token of an exchange (Core §2,
// §3.1.3.6, §12.2): the released claims first, then the protocol claims,
// which they cannot override.
func (p *Provider) signIDToken(ctx context.Context, iss oauth2.TokenIssuance, gc grantContext, claims map[string]any) (string, error) {
	clientID := iss.Client.ID()

	// RFC 9068 §5, RFC 8725 §3.12: an access token never shares the ID
	// Token's audience. Only the requesting client's ID is compared: an
	// audience naming another client is the configuration's to prevent
	// (IssuerResolver audiences are never client IDs).
	if iss.Access.Audience == clientID {
		return "", errAudienceCollision
	}

	if _, err := p.parseIssuer(iss.Access.Issuer); err != nil {
		return "", err
	}

	snap, err := p.keys(ctx, iss.Access.Issuer)
	if err != nil {
		return "", err
	}

	key, err := signingKey(snap, iss.Client)
	if err != nil {
		return "", err
	}

	hashed, err := atHash(key.Algorithm, iss.Access.Token)
	if err != nil {
		return "", err
	}

	issuedAt := iss.Access.IssuedAt

	claims[claimIss] = iss.Access.Issuer
	claims[claimSub] = iss.Access.Subject
	claims[claimAud] = clientID
	claims[claimIat] = issuedAt.Unix()
	claims[claimExp] = issuedAt.Add(p.ttl).Unix()
	claims[claimAuthTime] = gc.AuthTime
	claims[claimAtHash] = hashed

	// The code's nonce, at the code exchange only (Core §12.2).
	if iss.GrantType == oauth2.GrantTypeAuthorizationCode && iss.Nonce != "" {
		claims[claimNonce] = iss.Nonce
	}

	if gc.ACR != "" {
		claims[claimACR] = gc.ACR
	}

	if len(gc.AMR) > 0 {
		claims[claimAMR] = gc.AMR
	}

	signer, err := jwtsec.NewSigner(key)
	if err != nil {
		return "", fmt.Errorf("oidcprovider: sign ID Token: %w", err)
	}

	jws, err := signer.Sign(ctx, claims)
	if err != nil {
		return "", fmt.Errorf("oidcprovider: sign ID Token: %w", err)
	}

	return jws, nil
}

// atHash computes at_hash (Core §3.1.3.6): the base64url left half of the
// hash of the access token, with the hash function of alg.
func atHash(alg jwtsec.Algorithm, accessToken string) (string, error) {
	var h hash.Hash

	switch {
	case strings.HasSuffix(string(alg), "256"):
		h = sha256.New()
	case strings.HasSuffix(string(alg), "384"):
		h = sha512.New384()
	case strings.HasSuffix(string(alg), "512"):
		h = sha512.New()
	default:
		return "", fmt.Errorf("oidcprovider: no at_hash function for %s", alg)
	}

	h.Write([]byte(accessToken))
	sum := h.Sum(nil)

	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2]), nil
}
