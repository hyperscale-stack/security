// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"net/http"
)

type Server struct {
	cfg *Configuration
}

func NewServer(options ...Option) *Server {
	s := &Server{}

	for _, opt := range options {
		opt(s)
	}

	return s
}

func (s *Server) HandleAccessRequest(w http.ResponseWriter, r *http.Request) *AccessRequest {
	// Only allow GET or POST
	if r.Method == http.MethodGet {
		if !s.cfg.AllowGetAccessRequest {
			//s.setErrorAndLog(w, E_INVALID_REQUEST, errors.New("Request must be POST"), "access_request=%s", "GET request not allowed")
			return nil
		}
	} else if r.Method != http.MethodPost {
		//s.setErrorAndLog(w, E_INVALID_REQUEST, errors.New("Request must be POST"), "access_request=%s", "request must be POST")
		return nil
	}

	if err := r.ParseForm(); err != nil {
		//s.setErrorAndLog(w, E_INVALID_REQUEST, err, "access_request=%s", "parsing error")
		return nil
	}

	grantType := AccessRequestType(r.FormValue("grant_type"))
	if s.cfg.AllowedAccessTypes.Exists(grantType) {
		switch grantType {
		case AUTHORIZATION_CODE:
			// return s.handleAuthorizationCodeRequest(w, r)
		case REFRESH_TOKEN:
			// return s.handleRefreshTokenRequest(w, r)
		case PASSWORD:
			// return s.handlePasswordRequest(w, r)
		case CLIENT_CREDENTIALS:
			// return s.handleClientCredentialsRequest(w, r)
		case ASSERTION:
			// return s.handleAssertionRequest(w, r)
		}
	}

	// s.setErrorAndLog(w, E_UNSUPPORTED_GRANT_TYPE, nil, "access_request=%s", "unknown grant type")
	return nil
}
