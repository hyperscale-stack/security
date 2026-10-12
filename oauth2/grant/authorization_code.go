// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grant

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"slices"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/pkce"
)

// AuthorizationCode implements RFC 6749 §4.1.3 with the RFC 7636 PKCE
// extension. The flow:
//
//  1. Derive the code's token family from its hash, then consume the code
//     atomically (single-use enforcement).
//  2. Refuse an expired code.
//  3. Re-bind client (code.ClientID MUST match the authenticated client)
//     and issuer (code.Issuer MUST match the issuer resolved for the
//     request: a code is redeemed in the realm that authorized it, OIDC
//     Core §16.15).
//  4. Re-bind redirect_uri (RFC 6749 §4.1.3 paragraph 7).
//  5. Verify PKCE when present / required, then check that the client may
//     use the grant. A code issued without code_challenge is refused when
//     the request carries a code_verifier, under every profile: the PKCE
//     downgrade attack (RFC 9700 §2.1.1, §4.8.2) strips code_challenge from
//     an attacker's own authorization request to inject the code it gets
//     into a victim's session. The code is burned. This refusal applies to
//     issuance only: a replay of a code redeemed without PKCE still revokes
//     its family (see below), whatever code_verifier it carries.
//  6. Generate the access token (+ optional refresh token) in the code's
//     family, carrying its issuer and grant context, let the server's
//     extension extend the response (an OpenID Connect id_token, with the
//     code's nonce), persist both atomically and return the pair.
//
// A replay — the store still retains the consumed code — is refused with
// invalid_grant. When the replay passes steps 2-5 itself, proving
// possession of the code the way its first exchange had to, the code's
// family is revoked (RFC 6749 §4.1.2, RFC 9700 §4.2.4): every token the
// code issued stops working, and an exchange of the code still in flight
// fails at step 6 with invalid_grant instead of issuing, while the store
// keeps the family's revoked record (see [oauth2.Storage]). A replay
// failing those steps — another client or issuer, a missing or wrong
// verifier, another redirect_uri, an expired code — revokes nothing
// (OAuth 2.1 §4.1.3, §7.5.3).
type AuthorizationCode struct {
	cfg Config
}

// NewAuthorizationCode constructs the handler.
func NewAuthorizationCode(cfg Config) *AuthorizationCode {
	if cfg.Storage == nil || cfg.AccessTokens == nil {
		panic("oauth2/grant: NewAuthorizationCode requires Storage and AccessTokens")
	}

	return &AuthorizationCode{cfg: cfg}
}

// Type implements [Grant].
func (g *AuthorizationCode) Type() string { return oauth2.GrantTypeAuthorizationCode }

// Handle implements [Grant].
func (g *AuthorizationCode) Handle(ctx context.Context, req Request) (*Response, error) {
	rawCode := req.Form.Get("code")
	if rawCode == "" {
		return nil, oauth2.ErrInvalidRequest.WithDescription("missing code")
	}

	hash := oauth2.HashToken(nil, rawCode) // pepper-free: code only lives in storage briefly
	// Fixed before the code is consumed: a replay can revoke the family
	// even while the first exchange is still issuing into it.
	familyID := codeFamilyID(hash)

	code, err := g.cfg.Storage.ConsumeAuthorizationCode(ctx, hash)

	// A replay without its record — a typed nil included — cannot be
	// validated: it is refused like an unknown code.
	var replay *oauth2.CodeReplayError
	if errors.As(err, &replay) && replay != nil && replay.Record != nil {
		g.revokeReplayed(ctx, req, replay.Record, familyID)

		return nil, oauth2.ErrCodeAlreadyUsed
	}

	if err != nil {
		return nil, err //nolint:wrapcheck // oauth2.* sentinels pass through
	}

	if err := g.validateExchange(req, code); err != nil {
		return nil, err
	}

	if code.CodeChallenge == "" && hasCodeVerifier(req.Form) {
		return nil, oauth2.ErrInvalidGrant.WithDescription("code_verifier sent for a code issued without code_challenge")
	}

	return issueTokenPair(ctx, g.cfg, req, issuance{
		grantType: oauth2.GrantTypeAuthorizationCode, nonce: code.Nonce,
		subject: code.Subject, scope: code.Scope, refreshScope: code.Scope,
		familyID: familyID, extensionData: code.ExtensionData,
	})
}

// hasCodeVerifier reports whether form carries a code_verifier with a
// value — any of its occurrences: a parameter without value is omitted
// (RFC 6749 §3.1), not a way to hide a repeated one.
func hasCodeVerifier(form url.Values) bool {
	return slices.ContainsFunc(form["code_verifier"], func(v string) bool { return v != "" })
}

// validateExchange checks that req may redeem code, in order: the code has
// not expired, was issued to the authenticated client, under the issuer
// resolved for the request, for the same redirect_uri (RFC 6749 §4.1.3),
// its PKCE verifier matches when present or required (RFC 7636 §4.6), and
// the client may use the grant. A replay passing it proves possession of
// the code. A code stored without an issuer — before codes recorded it —
// only matches a request whose resolved issuer is empty too: it fails
// closed.
func (g *AuthorizationCode) validateExchange(req Request, code *oauth2.AuthorizationCode) error {
	if code.IsExpired(req.Now) {
		return oauth2.ErrInvalidGrant.WithDescription("authorization code expired")
	}

	if code.ClientID != req.Client.ID() {
		return oauth2.ErrInvalidGrant.WithDescription("code issued for a different client")
	}

	if code.Issuer != req.Issuer {
		return oauth2.ErrInvalidGrant.WithDescription("authorization code issued by another issuer")
	}

	if redirect := req.Form.Get("redirect_uri"); redirect != code.RedirectURI {
		return oauth2.ErrInvalidGrant.WithDescription("redirect_uri mismatch")
	}

	if err := g.verifyPKCE(req, code); err != nil {
		return err
	}

	return checkGrantType(req.Client, oauth2.GrantTypeAuthorizationCode)
}

// revokeReplayed answers the replay of a consumed code (RFC 6749 §4.1.2).
// When req would have been accepted for code, it revokes the code's
// family on a context detached from the request
// ([Config.revokeFamilyDetached]) and reports a failure to the error hook,
// since the client gets invalid_grant either way. Any other replay revokes
// nothing: it could not have redeemed the code itself, and revoking on its
// say-so would let anyone holding a leaked code, or naming a public
// client_id, cut the client off.
func (g *AuthorizationCode) revokeReplayed(ctx context.Context, req Request, code *oauth2.AuthorizationCode, familyID string) {
	if g.validateExchange(req, code) != nil {
		return
	}

	if err := g.cfg.revokeFamilyDetached(ctx, familyID); err != nil {
		g.cfg.notifyError(ctx, oauth2.ErrServerError.
			WithDescription("revoke token family failed after authorization code replay").
			WithCause(err))
	}
}

func (g *AuthorizationCode) verifyPKCE(req Request, code *oauth2.AuthorizationCode) error {
	verifier := req.Form.Get("code_verifier")

	// PKCE is required when the grant is explicitly configured for it, when
	// the active profile mandates it (BCP / OAuth 2.1), and under every
	// profile for a client that is not confidential (RFC 9700 §2.1.1:
	// public clients MUST use PKCE). Each can only tighten the rule.
	pkceRequired := g.cfg.RequirePKCE || req.Profile.RequiresPKCE() || req.Client.Type() != oauth2.ClientConfidential

	if code.CodeChallenge == "" {
		if pkceRequired {
			return oauth2.ErrInvalidGrant.WithDescription("PKCE required")
		}

		return nil
	}

	if verifier == "" {
		return oauth2.ErrInvalidGrant.WithDescription("missing code_verifier")
	}

	method := pkce.Method(code.CodeChallengeMethod)
	if method == "" {
		method = pkce.MethodPlain
	}

	// The "plain" transformation is accepted only when the profile tolerates
	// it (Profile20). BCP and OAuth 2.1 mandate S256.
	if method == pkce.MethodPlain && !req.Profile.AllowsPKCEPlain() {
		return oauth2.ErrInvalidGrant.WithDescription("PKCE method plain is refused by the active profile")
	}

	// RFC 7636 §4.1: a code_verifier is 43-128 unreserved characters. A
	// malformed one cannot be a valid proof, and §4.6 answers a failed
	// proof with invalid_grant. The code stays consumed.
	if !pkce.ValidVerifier(verifier) {
		return oauth2.ErrInvalidGrant.WithDescription("malformed code_verifier")
	}

	if !pkce.Verify(method, verifier, code.CodeChallenge) {
		return oauth2.ErrInvalidGrant.WithDescription("PKCE verification failed")
	}

	return nil
}

// codeFamilyPrefix domain-separates the token family derived from a code
// hash from any other use of the hash.
const codeFamilyPrefix = "oauth2/code-family:"

// codeFamilyID derives the token family of the tokens a code issues from
// the code's storage hash: 16 bytes of a domain-separated SHA-256,
// base64url -> 22 chars without padding, like [newFamilyID]. The exchange
// and every replay of the code compute it before consuming the code, so
// linking a code to its tokens takes no storage, and a replay can revoke
// the family before the first exchange has issued into it.
func codeFamilyID(codeHash string) string {
	sum := sha256.Sum256([]byte(codeFamilyPrefix + codeHash))

	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

// newFamilyID returns a 16-byte random identifier grouping every access /
// refresh token issued from one authorization that has no code to derive
// it from (the legacy password grant). base64url -> 22 chars without
// padding.
func newFamilyID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}
