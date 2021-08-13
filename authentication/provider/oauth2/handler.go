// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/hyperscale-stack/logger"
	"github.com/hyperscale-stack/security/authentication/credential"
)

var (
	ErrRequestMustBePost = errors.New("request must be POST")
)

func (s Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case s.cfg.PrefixURI + "/token":
		s.handleTokenRequest(w, r)
	case s.cfg.PrefixURI + "/authorize":
		s.handleAuthorizeRequest(w, r)
	}
}

func (s Server) handleTokenRequest(w http.ResponseWriter, r *http.Request) {
	// Only allow GET or POST
	if r.Method == http.MethodGet {
		if !s.cfg.AllowGetAccessRequest {
			s.error(w, E_INVALID_REQUEST, ErrRequestMustBePost, "access_request=%s", "GET request not allowed")

			return
		}
	} else if r.Method != http.MethodPost {
		s.error(w, E_INVALID_REQUEST, ErrRequestMustBePost, "access_request=%s", "request must be POST")

		return
	}

	if err := r.ParseForm(); err != nil {
		s.error(w, E_INVALID_REQUEST, err, "access_request=%s", "parsing error")

		return
	}

	var ar *AccessRequest

	grantType := AccessRequestType(r.FormValue("grant_type"))
	if s.cfg.AllowedAccessTypes.Exists(grantType) {
		switch grantType {
		case AUTHORIZATION_CODE:
			// s.handleAuthorizationCodeRequest(w, r)
			ar.Authorized = true
		case REFRESH_TOKEN:
			// s.handleRefreshTokenRequest(w, r)
			ar.Authorized = true
		case PASSWORD:
			ar = s.handlePasswordRequest(w, r)

			user, err := s.userProvider.Authenticate(ar.Username, ar.Password)
			if err != nil {
				s.error(w, E_ACCESS_DENIED, err, "get_user=%s", "failed")

				return
			}

			ar.Authorized = true
			ar.UserData = user.GetID()

		case CLIENT_CREDENTIALS:
			// s.handleClientCredentialsRequest(w, r)
			ar.Authorized = true
		case ASSERTION:
			// s.handleAssertionRequest(w, r)
			ar.Authorized = false
		default:
			s.error(w, E_UNSUPPORTED_GRANT_TYPE, nil, "access_request=%s", "unknown grant type")

			return
		}

		s.FinishAccessRequest(w, r, ar)
	}

}

func (s Server) handleAuthorizeRequest(w http.ResponseWriter, r *http.Request) {

}

func (s Server) handlePasswordRequest(w http.ResponseWriter, r *http.Request) *AccessRequest {
	// get client authentication
	auth := s.getClientAuth(w, r, s.cfg.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}

	// generate access token
	ar := &AccessRequest{
		Type:            PASSWORD,
		Username:        r.FormValue("username"),
		Password:        r.FormValue("password"),
		Scope:           r.FormValue("scope"),
		GenerateRefresh: true,
		Expiration:      s.cfg.AccessExpiration,
		HttpRequest:     r,
	}

	// "username" and "password" is required
	if ar.Username == "" || ar.Password == "" {
		s.error(w, E_INVALID_GRANT, nil, "handle_password=%s", "username and password required")

		return nil
	}

	// must have a valid client
	if ar.Client = s.getClient(auth, s.storage, w, true); ar.Client == nil {
		return nil
	}

	// set redirect uri
	ar.RedirectURI = FirstURI(ar.Client.GetRedirectURI(), s.cfg.RedirectUriSeparator)

	/*
		user, err := s.userProvider.Authenticate(username, password)
		if err != nil && errors.Is(err, ErrUserNotFound) {
			s.error(w, E_ACCESS_DENIED, nil, "get_user=%s", "username or password is invalid")

			return
		} else if err != nil {
			s.error(w, E_ACCESS_DENIED, nil, "get_user=%s", "username or password is invalid")
		}
	*/

	return ar
}

// Returns the first uri from an uri list
func FirstURI(baseUriList string, separator string) string {
	if separator == "" {
		return baseUriList
	}

	if slist := strings.Split(baseUriList, separator); len(slist) > 0 {
		return slist[0]
	}

	return ""
}

// getClientAuth checks client basic authentication in params if allowed,
// otherwise gets it from the header.
// Sets an error on the response if no auth is present or a server error occurs.
func (s Server) getClientAuth(w http.ResponseWriter, r *http.Request, allowQueryParams bool) *credential.UsernamePasswordCredential {
	ctx := r.Context()

	// creds := credential.FromContext(ctx)

	if allowQueryParams {
		// Allow for auth without password
		if _, hasSecret := r.Form["client_secret"]; hasSecret {
			auth := credential.NewUsernamePasswordCredential(
				r.FormValue("client_id"),
				r.FormValue("client_secret"),
			)

			if auth.GetPrincipal() != "" {
				return auth.(*credential.UsernamePasswordCredential)
			}
		}
	}

	auth := credential.FromContext(ctx)

	/*
		auth, err := CheckBasicAuth(r)
		if err != nil {
			s.setErrorAndLog(w, E_INVALID_REQUEST, err, "get_client_auth=%s", "check auth error")
			return nil
		}
	*/
	if auth == nil {
		s.error(w, E_INVALID_REQUEST, errors.New("Client authentication not sent"), "get_client_auth=%s", "client authentication not sent")

		return nil
	}

	return auth.(*credential.UsernamePasswordCredential)
}

// getClient looks up and authenticates the basic auth using the given
// storage. Sets an error on the response if auth fails or a server error occurs.
func (s Server) getClient(creds *credential.UsernamePasswordCredential, storage StorageProvider, w http.ResponseWriter, allowEmptySecret bool) Client {
	client, err := storage.LoadClient(creds.GetPrincipal().(string))
	if errors.Is(err, ErrClientNotFound) {
		s.error(w, E_UNAUTHORIZED_CLIENT, nil, "get_client=%s", "not found")

		return nil
	} else if err != nil {
		s.error(w, E_SERVER_ERROR, err, "get_client=%s", "error finding client")

		return nil
	}

	if client == nil {
		s.error(w, E_UNAUTHORIZED_CLIENT, nil, "get_client=%s", "client is nil")

		return nil
	}

	if c, ok := client.(ClientSecretMatcher); ok {
		if creds.GetCredentials() != nil && !c.SecretMatches(creds.GetCredentials().(string)) {
			s.error(w, E_UNAUTHORIZED_CLIENT, nil, "get_client=%s, client_id=%v", "client check failed", client.GetID())

			return nil
		} else if creds.GetCredentials() == nil && !allowEmptySecret {
			s.error(w, E_UNAUTHORIZED_CLIENT, nil, "get_client=%s, client_id=%v", "client check failed", client.GetID())

			return nil
		}
	} else if !allowEmptySecret {
		s.error(w, E_UNAUTHORIZED_CLIENT, nil, "get_client=%s, client_id=%v", "client check failed", client.GetID())

		return nil
	}

	if client.GetRedirectURI() == "" {
		s.error(w, E_UNAUTHORIZED_CLIENT, nil, "get_client=%s", "client redirect uri is empty")

		return nil
	}

	return client
}

func (s Server) error(w http.ResponseWriter, responseError DefaultErrorID, internalError error, debugFormat string, debugArgs ...interface{}) {
	format := "error=%v, internal_error=%#v " + debugFormat

	s.logger.Error(
		format,
		logger.WithFormat(append([]interface{}{responseError, internalError}, debugArgs...)...),
	)
}

func (s *Server) FinishAccessRequest(w http.ResponseWriter, r *http.Request, ar *AccessRequest) {
	// don't process if is already an error
	/*if w.IsError {
		return
	}*/

	redirectURI := r.FormValue("redirect_uri")
	// Get redirect uri from AccessRequest if it's there (e.g., refresh token request)
	if ar.RedirectURI != "" {
		redirectURI = ar.RedirectURI
	}

	if !ar.Authorized {
		s.error(w, E_ACCESS_DENIED, nil, "finish_access_request=%s", "authorization failed")

		return
	}

	var ret *AccessInfo
	var err error

	if ar.ForceAccessInfo == nil {
		// generate access token
		ret = &AccessInfo{
			Client:        ar.Client,
			AuthorizeInfo: ar.AuthorizeInfo,
			AccessInfo:    ar.AccessInfo,
			RedirectURI:   redirectURI,
			CreatedAt:     s.now(),
			ExpiresIn:     int64(ar.Expiration.Seconds()),
			UserData:      ar.UserData,
			Scope:         ar.Scope,
		}

		// generate access token
		ret.AccessToken, ret.RefreshToken, err = s.tokenGenerator.GenerateAccessToken(ar.GenerateRefresh)
		if err != nil {
			s.error(w, E_SERVER_ERROR, err, "finish_access_request=%s", "error generating token")

			return
		}
	} else {
		ret = ar.ForceAccessInfo
	}

	// save access token
	if err = s.storage.SaveAccess(ret); err != nil {
		s.error(w, E_SERVER_ERROR, err, "finish_access_request=%s", "error saving access token")

		return
	}

	// remove authorization token
	if ret.AuthorizeInfo != nil {
		s.storage.RemoveAuthorize(ret.AuthorizeInfo.Code)
	}

	// remove previous access token
	if ret.AccessInfo != nil && !s.cfg.RetainTokenAfterRefresh {
		if ret.AccessInfo.RefreshToken != "" {
			s.storage.RemoveRefresh(ret.AccessInfo.RefreshToken)
		}

		s.storage.RemoveAccess(ret.AccessInfo.AccessToken)
	}

	output := map[string]interface{}{
		"access_token": ret.AccessToken,
		"token_type":   s.cfg.TokenType,
		"expires_in":   ret.ExpiresIn,
	}

	if ret.RefreshToken != "" {
		output["refresh_token"] = ret.RefreshToken
	}

	if ret.Scope != "" {
		output["scope"] = ret.Scope
	}

	if err := json.NewEncoder(w).Encode(output); err != nil {
		s.error(w, E_SERVER_ERROR, err, "finish_access_request=%s", "serialize response failed")

		return
	}

}
