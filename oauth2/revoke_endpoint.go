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
// The answer is 200 OK whether or not the token existed or belonged to the
// caller (RFC 7009 §2.2), and 503 temporarily_unavailable when a storage
// failure leaves the revocation unfinished (RFC 7009 §2.2.1): the token's
// lookup failed, its family could not be revoked, or — for a token outside
// any family — it could not be deleted. The client then retries, which
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

	client, _, _, err := s.authenticateClientAt(r.Context(), r)
	if err != nil {
		s.writeOAuthError(r.Context(), w, err)

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
	if !s.revoke(r.Context(), client, rawToken) {
		writeErrorResponse(w, errRevocationUnavailable)

		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
}

// revoke revokes rawToken when it is an access or a refresh token of
// client, and reports whether the token can no longer be used: true when it
// was revoked, is unknown, or belongs to another client; false when a
// lookup or a revocation failed and the token may still be usable. Each
// failure is reported to the [ErrorHook]; an unknown token is not.
func (s *Server) revoke(ctx context.Context, client Client, rawToken string) bool {
	hash := HashToken(nil, rawToken)

	at, err := s.cfg.Storage.LookupAccessToken(ctx, hash)
	if err == nil {
		return s.revokeAccess(ctx, client, at, hash)
	}

	if !s.lookupMissed(ctx, err) {
		return false
	}

	rt, err := s.cfg.Storage.LookupRefreshToken(ctx, hash)
	if err != nil {
		return s.lookupMissed(ctx, err)
	}

	if rt.ClientID != client.ID() || rt.FamilyID == "" {
		return true
	}

	return s.revokeFamily(ctx, rt.FamilyID)
}

// lookupMissed reports whether a failed lookup merely missed the token:
// invalid_grant, for a token that is unknown, expired from the store, or of
// a revoked family. Any other failure leaves the token possibly usable and
// is reported to the [ErrorHook].
func (s *Server) lookupMissed(ctx context.Context, err error) bool {
	if IsCode(err) == CodeInvalidGrant {
		return true
	}

	s.notifyError(ctx, ErrServerError.WithDescription("revoke: token lookup failed").WithCause(err))

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
func (s *Server) revokeAccess(ctx context.Context, client Client, at *AccessToken, hash string) bool {
	if at.ClientID != client.ID() {
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
