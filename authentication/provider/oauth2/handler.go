// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"errors"
	"net/http"
)

var (
	ErrOAuthError = errors.New("oauth2 error")
)

func (s Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//nolint:wsl,gocritic
	//@TODO: WIP
	switch r.URL.Path {
	case s.cfg.PrefixURI + "/token":
		s.handleTokenRequest(w, r)
		/*
			case s.cfg.PrefixURI + "/authorize":
					s.handleAuthorizeRequest(w, r)
		*/
	}
}

func (s Server) handleTokenRequest(w http.ResponseWriter, r *http.Request) {
	resp := s.NewResponse()

	requestType := ""

	if ar := s.HandleAccessRequest(resp, r); ar != nil {
		requestType = string(ar.Type)

		//nolint:exhaustive
		switch ar.Type {
		case AUTHORIZATION_CODE:
			ar.Authorized = true
		case REFRESH_TOKEN:
			ar.Authorized = true
		case PASSWORD:
			user, err := s.userProvider.Authenticate(ar.Username, ar.Password)
			if err != nil {
				s.setErrorAndLog(resp, E_ACCESS_DENIED, err, "get_user=%s", "failed")
			} else {
				ar.Authorized = true
				ar.UserData = user.GetID()
			}
		case CLIENT_CREDENTIALS:
			ar.Authorized = true
		}

		s.FinishAccessRequest(resp, r, ar)
	}

	var err error

	if resp.IsError {
		if resp.InternalError != nil {
			err = resp.InternalError
		} else {
			err = ErrOAuthError
		}

		s.logger.Error(err.Error())

		s.emitter.Dispatch("oauth."+requestType+".failed", resp)
	} else {
		s.emitter.Dispatch("oauth."+requestType+".succeeded", resp)
	}

	if err := OutputJSON(resp, w, r); err != nil {
		s.logger.Error(err.Error())
	}
}
