// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"context"
	"net/http"
)

// RevokeHandler returns the http.Handler for RFC 7009 token revocation.
// Both access and refresh tokens are accepted; the server tries each
// kind in turn. Revocation of a refresh token also revokes the rest of
// its family (the BCP §8.10.3 reuse-detection mechanism reuses the same
// hammer).
//
// The handler always returns 200 OK on completion — RFC 7009 §2.2 says
// revocation requests MUST NOT leak whether the token existed.
func (s *Server) RevokeHandler() http.Handler {
	return http.HandlerFunc(s.serveRevoke)
}

func (s *Server) serveRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOAuthError(w, ErrInvalidRequest.WithDescription("POST required"))

		return
	}

	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, ErrInvalidRequest.WithCause(err))

		return
	}

	client, err := s.authenticateClient(r.Context(), r)
	if err != nil {
		writeOAuthError(w, err)

		return
	}

	rawToken := r.PostFormValue("token")
	if rawToken == "" {
		writeOAuthError(w, ErrInvalidRequest.WithDescription("missing token"))

		return
	}

	// RFC 7009 §2.1: the hint is optional. We try access then refresh
	// regardless so the caller's hint is treated as advisory.
	s.bestEffortRevoke(r.Context(), client, rawToken)

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
}

// bestEffortRevoke tries to revoke a token assuming it is an access token,
// then assuming it is a refresh token. The implementation is intentionally
// silent: per RFC 7009 §2.2, the response must not reveal whether the
// token existed.
func (s *Server) bestEffortRevoke(ctx context.Context, client Client, rawToken string) {
	hash := HashToken(nil, rawToken)

	if at, err := s.cfg.Storage.LookupAccessToken(ctx, hash); err == nil {
		if at.ClientID == client.ID() {
			_ = s.cfg.Storage.RevokeAccessToken(ctx, hash)

			if at.FamilyID != "" {
				_ = s.cfg.Storage.RevokeRefreshFamily(ctx, at.FamilyID)
			}
		}

		return
	}

	if rt, err := s.cfg.Storage.LookupRefreshToken(ctx, hash); err == nil {
		if rt.ClientID == client.ID() && rt.FamilyID != "" {
			_ = s.cfg.Storage.RevokeRefreshFamily(ctx, rt.FamilyID)
		}
	}
}
