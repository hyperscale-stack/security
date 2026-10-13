// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"context"
	"net/http"

	"github.com/hyperscale-stack/security/oauth2/internal/param"
)

// errRevocationUnavailable answers a revocation that may not have taken
// effect (RFC 7009 §2.2.1): the client must assume the token still exists,
// and may retry — revocation is idempotent.
var errRevocationUnavailable = newCoded(CodeTemporarilyUnavailable, "revocation temporarily unavailable", nil)

// RevokeHandler returns the http.Handler for RFC 7009 token revocation.
// The client authenticates at the issuer the request resolves to — one
// bound to other issuers is unknown there ([IssuerBoundClient]). Both
// access and refresh tokens are accepted; the server tries each kind in
// turn. Revoking a refresh token revokes its whole family, and
// revoking an access token revokes its family too (RFC 7009 §2.1).
//
// A client revokes its own tokens of that issuer only: a token issued to
// another client, or under another issuer (OpenID Connect Core §16.15:
// issuers are separate realms), is left untouched. RFC 7009 §2.1 has such a
// request refused with an error; the server answers it as an invalid token
// instead (§2.2), so that /revoke never confirms to whoever holds a token
// that it is valid for another client. A token recorded without issuer —
// written before tokens recorded one — is revoked by its client at any
// issuer: revocation only takes away.
//
// The answer is 200 OK whether or not the token existed or belonged to the
// caller (RFC 7009 §2.2), and 503 temporarily_unavailable when a failure
// leaves the revocation undone or unfinished (RFC 7009 §2.2.1): the client
// could not be authenticated for another reason than a refused credential
// (the IssuerResolver or the [ClientStore] failed), the token's lookup
// failed, its family could not be revoked, or — for a token outside any
// family — it could not be deleted. The client then retries, which
// redoes the whole revocation. Each storage failure reaches the
// [ErrorHook] once, as a server_error carrying its cause; the 503 is not
// reported again. A 503 hints that the token exists only when the backend
// fails while the caller presents it, a caller that already holds the
// token.
//
// token and token_type_hint, like the client credentials, are
// single-valued: a request including one more than once with a value is
// answered invalid_request (RFC 6749 §5.2) — which token it would revoke is
// ambiguous.
func (s *Server) RevokeHandler() http.Handler {
	return http.HandlerFunc(s.serveRevoke)
}

func (s *Server) serveRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeOAuthError(r.Context(), w, ErrInvalidRequest.WithDescription("POST required"))

		return
	}

	if err := s.parseRequestForm(w, r); err != nil {
		s.writeOAuthError(r.Context(), w, formRefusal(err))

		return
	}

	client, issuer, _, err := s.authenticateClientAt(r.Context(), r)
	if err != nil {
		s.refuseRevocation(r.Context(), w, err)

		return
	}

	// RFC 7009 §2.1: which token a request carrying two would revoke is
	// ambiguous.
	form, repeated := param.SingleValued(r.PostForm, tokenLookupParameters)
	if repeated != "" {
		s.writeOAuthError(r.Context(), w, repeatedParameter(repeated))

		return
	}

	rawToken := form.Get("token")
	if rawToken == "" {
		s.writeOAuthError(r.Context(), w, ErrInvalidRequest.WithDescription("missing token"))

		return
	}

	// RFC 7009 §2.1: the hint is optional. We try access then refresh
	// regardless so the caller's hint is treated as advisory.
	if !s.revoke(r.Context(), client, issuer, rawToken) {
		writeErrorResponse(w, errRevocationUnavailable)

		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
}

// refuseRevocation answers a revocation whose client could not be
// authenticated: as the protocol refusal it is (invalid_client,
// invalid_request), or — for a failure of the IssuerResolver, the
// ClientStore or an authenticator — temporarily_unavailable (RFC 7009
// §2.2.1: the revocation did not take place; the client must assume the
// token still exists, and may retry), the failure reported once.
func (s *Server) refuseRevocation(ctx context.Context, w http.ResponseWriter, err error) {
	if code := IsCode(err); code != "" && code != CodeServerError {
		s.writeOAuthError(ctx, w, err)

		return
	}

	s.notifyError(ctx, ErrServerError.WithDescription("revoke: client authentication failed").WithCause(err))
	writeErrorResponse(w, errRevocationUnavailable)
}

// revoke revokes rawToken when it is an access or a refresh token of
// client at issuer (ownedAt), and reports whether the token can no longer
// be used — as far as the caller is concerned: true when it was revoked, is
// unknown, or belongs to another client or issuer; false when a lookup or a
// revocation failed and the token may still be usable. Each failure is
// reported to the [ErrorHook]; an unknown token is not.
func (s *Server) revoke(ctx context.Context, client Client, issuer, rawToken string) bool {
	hash := HashToken(nil, rawToken)

	at, err := s.cfg.Storage.LookupAccessToken(ctx, hash)
	if err == nil {
		return s.revokeAccess(ctx, client, issuer, at, hash)
	}

	if !s.lookupMissed(ctx, err, "revoke: token lookup failed") {
		return false
	}

	rt, err := s.cfg.Storage.LookupRefreshToken(ctx, hash)
	if err != nil {
		return s.lookupMissed(ctx, err, "revoke: token lookup failed")
	}

	if !ownedAt(client, issuer, rt.ClientID, rt.Issuer) || rt.FamilyID == "" {
		return true
	}

	return s.revokeFamily(ctx, rt.FamilyID)
}

// ownedAt reports whether a token issued to clientID under tokenIssuer is
// client's at issuer: its own, and of this issuer (RFC 7009 §2.1; OpenID
// Connect Core §16.15: a client of one realm cannot revoke another
// realm's grants). A token recorded without issuer — written before tokens
// recorded one — is its client's at any issuer: revocation only takes away.
func ownedAt(client Client, issuer, clientID, tokenIssuer string) bool {
	return clientID == client.ID() && (tokenIssuer == "" || tokenIssuer == issuer)
}

// lookupMissed reports whether a failed lookup merely missed the token:
// invalid_grant, for a token that is unknown, expired from the store, or of
// a revoked family. Any other failure leaves the token's state unknown and
// is reported to the [ErrorHook] as a server_error described by what.
func (s *Server) lookupMissed(ctx context.Context, err error, what string) bool {
	if IsCode(err) == CodeInvalidGrant {
		return true
	}

	s.notifyError(ctx, ErrServerError.WithDescription(what).WithCause(err))

	return false
}

// revokeAccess revokes an access token once it is confirmed to belong to
// the calling client, and reports whether the token can no longer be used.
// Each failure is reported to the [ErrorHook].
//
// A token of a family is revoked through its family first (RFC 7009 §2.1).
// Should that fail, the token is left in place and the revocation reported
// unfinished, so that the retry it calls for redoes both. Once the family
// is revoked no token of it is usable, and deleting the access token is
// mere cleanup: a failed delete is reported but leaves the answer
// unchanged. A token outside any family only goes away when it is deleted.
func (s *Server) revokeAccess(ctx context.Context, client Client, issuer string, at *AccessToken, hash string) bool {
	if !ownedAt(client, issuer, at.ClientID, at.Issuer) {
		return true
	}

	if at.FamilyID != "" && !s.revokeFamily(ctx, at.FamilyID) {
		return false
	}

	if err := s.cfg.Storage.RevokeAccessToken(ctx, hash); err != nil {
		s.notifyError(ctx, ErrServerError.WithDescription("revoke access token failed").WithCause(err))

		return at.FamilyID != ""
	}

	return true
}

// revokeFamily revokes a refresh-token family and reports whether it did,
// handing a failure to the [ErrorHook] rather than dropping it.
func (s *Server) revokeFamily(ctx context.Context, familyID string) bool {
	if err := s.cfg.Storage.RevokeRefreshFamily(ctx, familyID); err != nil {
		s.notifyError(ctx, ErrServerError.WithDescription("revoke refresh family failed").WithCause(err))

		return false
	}

	return true
}
