// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grant

import (
	"context"
	"errors"

	"github.com/hyperscale-stack/security/oauth2"
)

// RefreshToken implements the RFC 6749 §6 refresh_token grant with the
// RFC 9700 §4.14.2 hardening: refresh-token rotation with reuse detection.
//
// The flow:
//
//  1. Look up the refresh token; a consumed one (rotated, or of a revoked
//     family) is reuse: revoke the family and refuse with invalid_grant —
//     whatever the client or issuer presenting it.
//  2. Re-bind client (refresh.ClientID MUST match the authenticated client)
//     and issuer (refresh.Issuer MUST match the issuer resolved for the
//     request; a token stored without one only matches an empty issuer).
//  3. Optionally narrow scope (RFC 6749 §6 forbids broadening).
//  4. Decide rotation before minting anything: mandatory under
//     [oauth2.Profile20BCP] and [oauth2.Profile21Draft], opt-in via
//     [Config.RotateRefreshTokens] under [oauth2.Profile20]. A rotation
//     that cannot be honored fails with server_error
//     ([ErrRotationRequiresGenerator]).
//  5. Mint a fresh access token.
//  6. When rotating, mint a fresh refresh token in the same family with
//     the presented token's scope (RFC 6749 §6) — every minted token keeps
//     the presented token's issuer and grant context, the authentication
//     event a refresh rests on never changes (OIDC Core §12.2, RFC 9068
//     §2.2.1) — then consume the old token
//     and persist the new pair in one atomic
//     [oauth2.RefreshTokenStore.RotateRefreshToken]; otherwise persist the
//     access token alone into the family. Either write fails, persisting
//     nothing, once the family is revoked — the refusal stays invalid_grant
//     — and a reuse the store detects is answered like step 1.
type RefreshToken struct {
	cfg Config
}

// ErrRotationRequiresGenerator reports a refresh_token grant that has to
// rotate refresh tokens but has no [Config.RefreshTokens] generator to mint
// the replacement. [oauth2.NewServer] refuses such a grant; should
// [RefreshToken.Handle] run anyway — called directly, or behind a decorator
// hiding [RefreshToken.ValidateProfile] — it fails with server_error
// carrying it as cause, before any token is minted or persisted.
var ErrRotationRequiresGenerator = errors.New("oauth2/grant: refresh-token rotation requires a RefreshTokens generator")

// Compile-time interface check: renaming ValidateProfile would otherwise
// silently drop the NewServer consistency check.
var _ oauth2.ProfileValidator = (*RefreshToken)(nil)

// NewRefreshToken constructs the handler.
func NewRefreshToken(cfg Config) *RefreshToken {
	if cfg.Storage == nil || cfg.AccessTokens == nil {
		panic("oauth2/grant: NewRefreshToken requires Storage and AccessTokens")
	}

	return &RefreshToken{cfg: cfg}
}

// Type implements [Grant].
func (g *RefreshToken) Type() string { return "refresh_token" }

// Handle implements [Grant].
func (g *RefreshToken) Handle(ctx context.Context, req Request) (*Response, error) {
	if !grantTypeAllowed(req.Client, "refresh_token") {
		return nil, oauth2.ErrUnauthorizedClient.WithDescription("client cannot use refresh_token")
	}

	raw := req.Form.Get("refresh_token")
	if raw == "" {
		return nil, oauth2.ErrInvalidRequest.WithDescription("missing refresh_token")
	}

	rtHash := oauth2.HashToken(nil, raw)

	rt, err := g.cfg.Storage.LookupRefreshToken(ctx, rtHash)
	if err != nil {
		return nil, err //nolint:wrapcheck // oauth2.* sentinels pass through
	}

	if rt.Consumed {
		// Reuse detected — revoke the whole family and refuse (RFC 9700
		// §4.14.2).
		g.revokeReusedFamily(ctx, rt.FamilyID)

		return nil, oauth2.ErrRefreshTokenReused
	}

	if rt.IsExpired(req.Now) {
		return nil, oauth2.ErrInvalidGrant.WithDescription("refresh_token expired")
	}

	if rt.ClientID != req.Client.ID() {
		return nil, oauth2.ErrInvalidGrant.WithDescription("refresh_token issued for a different client")
	}

	if rt.Issuer != req.Issuer {
		return nil, oauth2.ErrInvalidGrant.WithDescription("refresh_token issued by another issuer")
	}

	scope, err := narrowScopesForRefresh(req.Form.Get("scope"), rt.Scope)
	if err != nil {
		return nil, err
	}

	return g.issueRotated(ctx, req, rt, scope)
}

// rotates reports whether the exchange rotates the refresh token. The
// profile can only tighten [Config.RotateRefreshTokens], never relax it —
// the rule authorization_code applies to PKCE. Rotating needs a
// [Config.RefreshTokens] generator; without one it returns
// [ErrRotationRequiresGenerator].
func (g *RefreshToken) rotates(p oauth2.Profile) (bool, error) {
	if !g.cfg.RotateRefreshTokens && !p.RequiresRefreshRotation() {
		return false, nil
	}

	if g.cfg.RefreshTokens == nil {
		return false, ErrRotationRequiresGenerator
	}

	return true, nil
}

// ValidateProfile implements [oauth2.ProfileValidator]: it returns
// [ErrRotationRequiresGenerator] when the grant would have to rotate under
// p without a [Config.RefreshTokens] generator, so [oauth2.NewServer] fails
// at boot rather than on the first refresh.
func (g *RefreshToken) ValidateProfile(p oauth2.Profile) error {
	_, err := g.rotates(p)

	return err
}

func (g *RefreshToken) issueRotated(ctx context.Context, req Request, old *oauth2.RefreshToken, scope string) (*Response, error) {
	// Decided before anything is minted: a rotation that cannot be honored
	// must not mint an access token.
	rotate, err := g.rotates(req.Profile)
	if err != nil {
		return nil, oauth2.ErrServerError.WithCause(err)
	}

	iss := issuance{
		subject: old.Subject, scope: scope, refreshScope: old.Scope,
		familyID: old.FamilyID, extensionData: old.ExtensionData,
	}

	access, err := mintAccess(ctx, g.cfg, req, iss)
	if err != nil {
		return nil, err
	}

	pair := &oauth2.TokenPair{Access: *access}

	if !rotate {
		// The legacy Profile20 refresh: the access token alone joins the
		// family, which the store refuses once revoked.
		if err := g.cfg.Storage.SaveTokenPair(ctx, pair); err != nil {
			return nil, storageFailure(err)
		}

		return pairResponse(pair, scope), nil
	}

	// RFC 6749 §6: the new refresh token keeps the scope of the one it
	// replaces (iss.refreshScope); a narrowed request only narrows the
	// access token.
	if pair.Refresh, err = mintRefresh(ctx, g.cfg, req, iss); err != nil {
		return nil, err
	}

	if err := g.cfg.Storage.RotateRefreshToken(ctx, old.TokenHash, pair); err != nil {
		return nil, g.rotationFailure(ctx, old.FamilyID, err)
	}

	return pairResponse(pair, scope), nil
}

// rotationFailure maps a failed rotation. Reuse — the token was consumed
// since the lookup — answers the bare invalid_grant
// [oauth2.ErrRefreshTokenReused]; when the store could not revoke the
// family on that path, the revocation is retried as for a reuse the grant
// detects itself. Anything else goes through storageFailure.
func (g *RefreshToken) rotationFailure(ctx context.Context, familyID string, err error) error {
	if !errors.Is(err, oauth2.ErrRefreshTokenReused) {
		return storageFailure(err)
	}

	if errors.Is(err, oauth2.ErrTokenFamilyRevocationFailed) {
		g.revokeReusedFamily(ctx, familyID)
	}

	return oauth2.ErrRefreshTokenReused
}

// revokeReusedFamily answers a detected refresh-token reuse: it revokes the
// token's family on a context detached from the request
// ([Config.revokeFamilyDetached]) and reports a failure to the error hook,
// since the client gets invalid_grant either way. A token outside any
// family leaves nothing to revoke.
func (g *RefreshToken) revokeReusedFamily(ctx context.Context, familyID string) {
	if familyID == "" {
		return
	}

	if err := g.cfg.revokeFamilyDetached(ctx, familyID); err != nil {
		g.cfg.notifyError(ctx, oauth2.ErrServerError.
			WithDescription("revoke refresh family failed after reuse detection").
			WithCause(err))
	}
}

// narrowScopesForRefresh refuses broadening (RFC 6749 §6). An empty
// requested scope inherits the original grant's scope.
func narrowScopesForRefresh(requested, original string) (string, error) {
	if requested == "" {
		return original, nil
	}

	originalSet := make(map[string]struct{}, 8)

	for _, s := range splitScopes(original) {
		originalSet[s] = struct{}{}
	}

	for _, s := range splitScopes(requested) {
		if _, ok := originalSet[s]; !ok {
			return "", oauth2.ErrInvalidScope.WithDescription("refresh cannot broaden scope")
		}
	}

	return requested, nil
}

func splitScopes(s string) []string {
	out := make([]string, 0, 4)
	start := -1

	for i, r := range s {
		if r == ' ' || r == '\t' {
			if start >= 0 {
				out = append(out, s[start:i])
				start = -1
			}

			continue
		}

		if start < 0 {
			start = i
		}
	}

	if start >= 0 {
		out = append(out, s[start:])
	}

	return out
}
