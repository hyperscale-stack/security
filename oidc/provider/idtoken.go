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
	errAudienceCollision     = errors.New("oidcprovider: the access token audience is the client ID of a relying party of its issuer, an ID Token audience")
	errClientMismatch        = errors.New("oidcprovider: the access token belongs to another client, or one not registered at its issuer")
)

// invalidGrant is the refusal of a grant the provider cannot honor any more.
func invalidGrant(description string, cause error) error {
	return oauth2.ErrInvalidGrant.WithDescription(description).WithCause(cause)
}

// extendTokenResponse adds the ID Token to the response of a code exchange
// or a refresh whose tokens are minted but not persisted. For every
// exchange it first refuses an access-token audience naming a relying
// party (see checkAudience). For every exchange of a grant the provider
// approved it then checks the end-user is still valid — also when no ID
// Token comes out of it: a plain OAuth 2.0 grant, a refreshed scope
// lacking openid —, after the offline-access policy (Core §11) for an
// OpenID grant.
func (p *Provider) extendTokenResponse(ctx context.Context, iss oauth2.TokenIssuance) (oauth2.TokenResponseExtension, error) {
	gc, present, err := decodeContext(iss.Access.ExtensionData)
	if err != nil {
		return oauth2.TokenResponseExtension{}, invalidGrant("the grant cannot be honored", err)
	}

	if err := p.checkAudience(ctx, iss); err != nil {
		return oauth2.TokenResponseExtension{}, err
	}

	openID := hasScope(iss.Access.Scope, ScopeOpenID)

	switch {
	case !present && iss.GrantType == oauth2.GrantTypeAuthorizationCode && openID:
		// Core §3.1.3.2: a code redeemed for an ID Token must have been
		// issued for an OpenID request.
		return oauth2.TokenResponseExtension{}, invalidGrant("the code was not issued for an OpenID request", errContext)
	case !present:
		return oauth2.TokenResponseExtension{}, nil
	case gc.Plain && openID:
		return oauth2.TokenResponseExtension{}, invalidGrant("the grant cannot be honored", errContext)
	case gc.Plain:
		return oauth2.TokenResponseExtension{}, p.checkEndUser(ctx, iss)
	}

	if err := p.offlinePolicy(gc, iss); err != nil {
		return oauth2.TokenResponseExtension{}, err
	}

	if err := checkIssuanceClient(iss); err != nil {
		return oauth2.TokenResponseExtension{}, err
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
		return oauth2.TokenResponseExtension{}, sourceFailure(err, endUserGone)
	}

	if !openID {
		return oauth2.TokenResponseExtension{}, nil
	}

	released, err := p.names.releaseClaims(claims, allowed)
	if err != nil {
		return oauth2.TokenResponseExtension{}, err
	}

	idToken, err := p.signIDToken(ctx, iss, gc, released)
	if err != nil {
		return oauth2.TokenResponseExtension{}, err
	}

	return oauth2.TokenResponseExtension{IDToken: idToken}, nil
}

// checkIssuanceClient re-checks the TokenIssuance contract: the access
// token belongs to the authenticated client, registered at its issuer.
func checkIssuanceClient(iss oauth2.TokenIssuance) error {
	if iss.Client == nil || iss.Client.ID() != iss.Access.ClientID || !oauth2.ClientAllowsIssuer(iss.Client, iss.Access.Issuer) {
		return errClientMismatch
	}

	return nil
}

// checkEndUser checks, at an exchange of a plain OAuth 2.0 grant the
// provider approved, that the grant is the client's and that its end-user
// is still valid: a ClaimsQuery for an ID Token naming no claim.
func (p *Provider) checkEndUser(ctx context.Context, iss oauth2.TokenIssuance) error {
	if err := checkIssuanceClient(iss); err != nil {
		return err
	}

	_, err := p.cfg.Claims.Claims(ctx, ClaimsQuery{
		Issuer: iss.Access.Issuer, Subject: iss.Access.Subject, ClientID: iss.Access.ClientID, Target: ClaimsForIDToken,
	})
	if err != nil {
		return sourceFailure(err, endUserGone)
	}

	return nil
}

// endUserGone is the refusal of an exchange whose end-user the
// ClaimsSource no longer knows.
func endUserGone(cause error) error {
	return invalidGrant("the end-user is unknown or disabled", cause)
}

// checkAudience refuses an exchange whose access-token audience names a
// relying party of the token's issuer (see audienceNamesRP): that client,
// not checking typ — OpenID Connect Core §3.1.3.7 does not require it to —
// would take a JWT access token for one of its ID Tokens, whose aud is its
// client ID (Core §2). Explicit typing alone may not tell existing kinds of
// JWTs apart (RFC 8725 §3.11); distinct aud values for distinct kinds of
// JWTs of one issuer do (RFC 8725 §2.8, §3.12; RFC 9068 §5).
func (p *Provider) checkAudience(ctx context.Context, iss oauth2.TokenIssuance) error {
	rp, err := p.audienceNamesRP(ctx, iss.Access.Audience, iss.Access.Issuer, iss.Client)

	switch {
	case err != nil:
		return err
	case rp:
		return errAudienceCollision
	default:
		return nil
	}
}

// audienceNamesRP reports whether the access-token audience aud names a
// client the provider issues ID Tokens to at issuer: requester, compared
// without I/O, or the client the ClientStore returns for aud — its ID equal
// to aud — when registered at issuer (oauth2.ClientAllowsIssuer) and
// declaring the authorization_code grant. A client that cannot receive ID
// Tokens there — a resource server registered for introspection only, a
// client_credentials client, a client of another issuer — may be the
// audience. So may, by this rule, a client that declares refresh_token but
// no longer authorization_code, although it keeps refreshing the OpenID
// grants it holds: keep audiences apart from such clients' IDs too. An
// empty audience names none.
func (p *Provider) audienceNamesRP(ctx context.Context, aud, issuer string, requester oauth2.Client) (bool, error) {
	switch {
	case aud == "":
		return false, nil
	case requester != nil && aud == requester.ID():
		return true, nil
	}

	c, err := p.loadClient(ctx, aud)
	if err != nil {
		return false, err
	}

	return c != nil && c.ID() == aud && oauth2.ClientAllowsIssuer(c, issuer) &&
		oauth2.ClientAllowsGrantType(c, oauth2.GrantTypeAuthorizationCode), nil
}

// loadClient returns the client id of the server's ClientStore, nil for an
// unknown one — which the store answers with (nil, nil) or an
// invalid_client error (oauth2.ClientStore); any other error is a failure
// of the store.
func (p *Provider) loadClient(ctx context.Context, id string) (oauth2.Client, error) {
	c, err := p.clients.LoadClient(ctx, id)

	switch {
	case oauth2.IsCode(err) == oauth2.CodeInvalidClient:
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("oidcprovider: load client: %w", err)
	default:
		return c, nil
	}
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
