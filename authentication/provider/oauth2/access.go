// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/hyperscale-stack/logger"
	"github.com/hyperscale-stack/security/authentication/credential"
)

var (
	ErrRequestMustBePost         = errors.New("request must be POST")
	ErrExtraScope                = errors.New("the requested scope must not include any scope not originally granted by the resource owner")
	ErrClientIDNotSame           = errors.New("client id must be the same from previous token")
	ErrCodeChallengeNotSame      = errors.New("code_verifier failed comparison with code_challenge")
	ErrCodeVerifierInvalidFormat = errors.New("code_verifier has invalid format")
	ErrRedirectURINotSame        = errors.New("redirect uri is different")
)

// AccessRequestType is the type for OAuth2 param `grant_type`.
type AccessRequestType string

const (
	AUTHORIZATION_CODE AccessRequestType = "authorization_code"
	REFRESH_TOKEN      AccessRequestType = "refresh_token"
	PASSWORD           AccessRequestType = "password"
	CLIENT_CREDENTIALS AccessRequestType = "client_credentials"
	ASSERTION          AccessRequestType = "assertion"
	IMPLICIT           AccessRequestType = "__implicit"
)

// AccessRequest is a request for access tokens.
type AccessRequest struct {
	Type          AccessRequestType
	Code          string
	Client        Client
	AuthorizeData *AuthorizeData
	AccessData    *AccessData

	// Force finish to use this access data, to allow access data reuse
	ForceAccessData *AccessData
	RedirectURI     string
	Scope           string
	Username        string
	Password        string
	AssertionType   string
	Assertion       string

	// Set if request is authorized
	Authorized bool

	// Token expiration in seconds. Change if different from default
	Expiration time.Duration

	// Set if a refresh token should be generated
	GenerateRefresh bool

	// Data to be passed to storage. Not used by the library.
	UserData interface{}

	// HttpRequest *http.Request for special use
	HttpRequest *http.Request

	// Optional code_verifier as described in rfc7636
	CodeVerifier string
}

type accessCtxKey struct{}

// AccessTokenFromContext returns the Access Token info associated with the ctx.
func AccessTokenFromContext(ctx context.Context) *AccessData {
	if a, ok := ctx.Value(accessCtxKey{}).(*AccessData); ok {
		return a
	}

	return nil
}

// AccessTokenToContext returns new context with Access Token info.
func AccessTokenToContext(ctx context.Context, access *AccessData) context.Context {
	return context.WithValue(ctx, accessCtxKey{}, access)
}

// AccessData represents an access grant (tokens, expiration, client, etc).
type AccessData struct {
	// Client information
	Client Client

	// Authorize data, for authorization code
	AuthorizeData *AuthorizeData

	// Previous access data, for refresh token
	AccessData *AccessData

	// Access token
	AccessToken string

	// Refresh Token. Can be blank
	RefreshToken string

	// Token expiration in seconds
	ExpiresIn int64

	// Requested scope
	Scope string

	// Redirect URI from request
	RedirectURI string

	// Date created
	CreatedAt time.Time

	// Data to be passed to storage. Not used by the library.
	UserData interface{}
}

// IsExpired returns true if access expired.
func (i *AccessData) IsExpired() bool {
	return i.IsExpiredAt(time.Now())
}

// IsExpiredAt returns true if access expires at time 't'.
func (i *AccessData) IsExpiredAt(t time.Time) bool {
	return i.ExpireAt().Before(t)
}

// ExpireAt returns the expiration date.
func (i *AccessData) ExpireAt() time.Time {
	return i.CreatedAt.Add(time.Duration(i.ExpiresIn) * time.Second)
}

// HandleAccessRequest is the http.HandlerFunc for handling access token requests.
func (s *Server) HandleAccessRequest(w *Response, r *http.Request) *AccessRequest {
	// Only allow GET or POST
	if r.Method == http.MethodGet {
		if !s.cfg.AllowGetAccessRequest {
			s.setErrorAndLog(w, E_INVALID_REQUEST, ErrRequestMustBePost, "access_request=%s", "GET request not allowed")

			return nil
		}
	} else if r.Method != http.MethodPost {
		s.setErrorAndLog(w, E_INVALID_REQUEST, ErrRequestMustBePost, "access_request=%s", "request must be POST")

		return nil
	}

	if err := r.ParseForm(); err != nil {
		s.setErrorAndLog(w, E_INVALID_REQUEST, err, "access_request=%s", "parsing error")

		return nil
	}

	grantType := AccessRequestType(r.FormValue("grant_type"))
	if !s.cfg.AllowedAccessTypes.Exists(grantType) {
		s.setErrorAndLog(w, E_UNSUPPORTED_GRANT_TYPE, nil, "access_request=%s", "unknown grant type")

		return nil
	}

	//nolint: exhaustive
	switch grantType {
	case AUTHORIZATION_CODE:
		return s.handleAuthorizationCodeRequest(w, r)
	case REFRESH_TOKEN:
		return s.handleRefreshTokenRequest(w, r)
	case PASSWORD:
		return s.handlePasswordRequest(w, r)
	case CLIENT_CREDENTIALS:
		return s.handleClientCredentialsRequest(w, r)
	case ASSERTION:
		return s.handleAssertionRequest(w, r)
	default:
		s.setErrorAndLog(w, E_UNSUPPORTED_GRANT_TYPE, nil, "access_request=%s", "unknown grant type")

		return nil
	}
}

func (s *Server) handleAuthorizationCodeRequest(w *Response, r *http.Request) *AccessRequest {
	// get client authentication
	auth := s.getClientAuth(w, r, s.cfg.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}

	// generate access token
	ret := &AccessRequest{
		Type:            AUTHORIZATION_CODE,
		Code:            r.FormValue("code"),
		CodeVerifier:    r.FormValue("code_verifier"),
		RedirectURI:     r.FormValue("redirect_uri"),
		GenerateRefresh: true,
		Expiration:      s.cfg.AccessExpiration,
		HttpRequest:     r,
	}

	// "code" is required
	if ret.Code == "" {
		s.setErrorAndLog(w, E_INVALID_GRANT, nil, "auth_code_request=%s", "code is required")

		return nil
	}

	// must have a valid client
	if ret.Client = s.getClient(auth, w.Storage, w); ret.Client == nil {
		return nil
	}

	// must be a valid authorization code
	var err error

	ret.AuthorizeData, err = w.Storage.LoadAuthorize(ret.Code)
	if err != nil {
		s.setErrorAndLog(w, E_INVALID_GRANT, err, "auth_code_request=%s", "error loading authorize data")

		return nil
	}

	if ret.AuthorizeData == nil {
		s.setErrorAndLog(w, E_UNAUTHORIZED_CLIENT, nil, "auth_code_request=%s", "authorization data is nil")

		return nil
	}

	if ret.AuthorizeData.Client == nil {
		s.setErrorAndLog(w, E_UNAUTHORIZED_CLIENT, nil, "auth_code_request=%s", "authorization client is nil")

		return nil
	}

	if ret.AuthorizeData.Client.GetRedirectURI() == "" {
		s.setErrorAndLog(w, E_UNAUTHORIZED_CLIENT, nil, "auth_code_request=%s", "client redirect uri is empty")

		return nil
	}

	if ret.AuthorizeData.IsExpiredAt(s.now()) {
		s.setErrorAndLog(w, E_INVALID_GRANT, nil, "auth_code_request=%s", "authorization data is expired")

		return nil
	}

	// code must be from the client
	if ret.AuthorizeData.Client.GetID() != ret.Client.GetID() {
		s.setErrorAndLog(w, E_INVALID_GRANT, nil, "auth_code_request=%s", "client code does not match")

		return nil
	}

	// check redirect uri
	if ret.RedirectURI == "" {
		ret.RedirectURI = FirstURI(ret.Client.GetRedirectURI(), s.cfg.RedirectURISeparator)
	}

	if realRedirectURI, err := ValidateURIList(ret.Client.GetRedirectURI(), ret.RedirectURI, s.cfg.RedirectURISeparator); err != nil {
		s.setErrorAndLog(w, E_INVALID_REQUEST, err, "auth_code_request=%s", "error validating client redirect")

		return nil
	} else {
		ret.RedirectURI = realRedirectURI
	}

	if ret.AuthorizeData.RedirectURI != ret.RedirectURI {
		s.setErrorAndLog(w, E_INVALID_REQUEST, ErrRedirectURINotSame, "auth_code_request=%s", "client redirect does not match authorization data")

		return nil
	}

	// Verify PKCE, if present in the authorization data
	if len(ret.AuthorizeData.CodeChallenge) > 0 {
		// https://tools.ietf.org/html/rfc7636#section-4.1
		if matched := pkceMatcher.MatchString(ret.CodeVerifier); !matched {
			s.setErrorAndLog(
				w,
				E_INVALID_REQUEST,
				ErrCodeVerifierInvalidFormat,
				"auth_code_request=%s",
				"pkce code challenge verifier does not match",
			)

			return nil
		}

		// https: //tools.ietf.org/html/rfc7636#section-4.6
		codeVerifier := ""

		switch ret.AuthorizeData.CodeChallengeMethod {
		case "", PKCE_PLAIN:
			codeVerifier = ret.CodeVerifier
		case PKCE_S256:
			hash := sha256.Sum256([]byte(ret.CodeVerifier))
			codeVerifier = base64.RawURLEncoding.EncodeToString(hash[:])
		default:
			s.setErrorAndLog(
				w,
				E_INVALID_REQUEST,
				nil,
				"auth_code_request=%s",
				"pkce transform algorithm not supported (rfc7636)",
			)

			return nil
		}

		if codeVerifier != ret.AuthorizeData.CodeChallenge {
			s.setErrorAndLog(
				w,
				E_INVALID_GRANT,
				ErrCodeChallengeNotSame,
				"auth_code_request=%s",
				"pkce code verifier does not match challenge",
			)

			return nil
		}
	}

	// set rest of data
	ret.Scope = ret.AuthorizeData.Scope
	ret.UserData = ret.AuthorizeData.UserData

	return ret
}

func extraScopes(access_scopes, refresh_scopes string) bool {
	access_scopes_list := strings.Split(access_scopes, " ")
	refresh_scopes_list := strings.Split(refresh_scopes, " ")

	access_map := make(map[string]int)

	for _, scope := range access_scopes_list {
		if scope == "" {
			continue
		}

		access_map[scope] = 1
	}

	for _, scope := range refresh_scopes_list {
		if scope == "" {
			continue
		}

		if _, ok := access_map[scope]; !ok {
			return true
		}
	}

	return false
}

func (s *Server) handleRefreshTokenRequest(w *Response, r *http.Request) *AccessRequest {
	// get client authentication
	auth := s.getClientAuth(w, r, s.cfg.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}

	// generate access token
	ret := &AccessRequest{
		Type:            REFRESH_TOKEN,
		Code:            r.FormValue("refresh_token"),
		Scope:           r.FormValue("scope"),
		GenerateRefresh: true,
		Expiration:      s.cfg.AccessExpiration,
		HttpRequest:     r,
	}

	// "refresh_token" is required
	if ret.Code == "" {
		s.setErrorAndLog(w, E_INVALID_GRANT, nil, "refresh_token=%s", "refresh_token is required")

		return nil
	}

	// must have a valid client
	if ret.Client = s.getClient(auth, w.Storage, w); ret.Client == nil {
		return nil
	}

	// must be a valid refresh code
	var err error

	ret.AccessData, err = w.Storage.LoadRefresh(ret.Code)
	if err != nil {
		s.setErrorAndLog(w, E_INVALID_GRANT, err, "refresh_token=%s", "error loading access data")

		return nil
	}

	if ret.AccessData == nil {
		s.setErrorAndLog(w, E_UNAUTHORIZED_CLIENT, nil, "refresh_token=%s", "access data is nil")

		return nil
	}

	if ret.AccessData.Client == nil {
		s.setErrorAndLog(w, E_UNAUTHORIZED_CLIENT, nil, "refresh_token=%s", "access data client is nil")

		return nil
	}

	if ret.AccessData.Client.GetRedirectURI() == "" {
		s.setErrorAndLog(w, E_UNAUTHORIZED_CLIENT, nil, "refresh_token=%s", "access data client redirect uri is empty")

		return nil
	}

	// client must be the same as the previous token
	if ret.AccessData.Client.GetID() != ret.Client.GetID() {
		s.setErrorAndLog(
			w,
			E_INVALID_CLIENT,
			ErrClientIDNotSame,
			"refresh_token=%s, current=%v, previous=%v",
			"client mismatch",
			ret.Client.GetID(),
			ret.AccessData.Client.GetID(),
		)

		return nil
	}

	// set rest of data
	ret.RedirectURI = ret.AccessData.RedirectURI
	ret.UserData = ret.AccessData.UserData

	if ret.Scope == "" {
		ret.Scope = ret.AccessData.Scope
	}

	if extraScopes(ret.AccessData.Scope, ret.Scope) {
		s.setErrorAndLog(w, E_ACCESS_DENIED, ErrExtraScope, "refresh_token=%s", ErrExtraScope.Error())

		return nil
	}

	return ret
}

//nolint:dupl
func (s *Server) handlePasswordRequest(w *Response, r *http.Request) *AccessRequest {
	// get client authentication
	auth := s.getClientAuth(w, r, s.cfg.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}

	// generate access token
	ret := &AccessRequest{
		Type:            PASSWORD,
		Username:        r.FormValue("username"),
		Password:        r.FormValue("password"),
		Scope:           r.FormValue("scope"),
		GenerateRefresh: true,
		Expiration:      s.cfg.AccessExpiration,
		HttpRequest:     r,
	}

	// "username" and "password" is required
	if ret.Username == "" || ret.Password == "" {
		s.setErrorAndLog(w, E_INVALID_GRANT, nil, "handle_password=%s", "username and pass required")

		return nil
	}

	// must have a valid client
	if ret.Client = s.getClient(auth, w.Storage, w); ret.Client == nil {
		return nil
	}

	// set redirect uri
	ret.RedirectURI = FirstURI(ret.Client.GetRedirectURI(), s.cfg.RedirectURISeparator)

	return ret
}

func (s *Server) handleClientCredentialsRequest(w *Response, r *http.Request) *AccessRequest {
	// get client authentication
	auth := s.getClientAuth(w, r, s.cfg.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}

	// generate access token
	ret := &AccessRequest{
		Type:            CLIENT_CREDENTIALS,
		Scope:           r.FormValue("scope"),
		GenerateRefresh: false,
		Expiration:      s.cfg.AccessExpiration,
		HttpRequest:     r,
	}

	// must have a valid client
	if ret.Client = s.getClient(auth, w.Storage, w); ret.Client == nil {
		return nil
	}

	// set redirect uri
	ret.RedirectURI = FirstURI(ret.Client.GetRedirectURI(), s.cfg.RedirectURISeparator)

	return ret
}

//nolint:dupl
func (s *Server) handleAssertionRequest(w *Response, r *http.Request) *AccessRequest {
	// get client authentication
	auth := s.getClientAuth(w, r, s.cfg.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}

	// generate access token
	ret := &AccessRequest{
		Type:            ASSERTION,
		Scope:           r.FormValue("scope"),
		AssertionType:   r.FormValue("assertion_type"),
		Assertion:       r.FormValue("assertion"),
		GenerateRefresh: false, // assertion should NOT generate a refresh token, per the RFC
		Expiration:      s.cfg.AccessExpiration,
		HttpRequest:     r,
	}

	// "assertion_type" and "assertion" is required
	if ret.AssertionType == "" || ret.Assertion == "" {
		s.setErrorAndLog(w, E_INVALID_GRANT, nil, "handle_assertion_request=%s", "assertion and assertion_type required")

		return nil
	}

	// must have a valid client
	if ret.Client = s.getClient(auth, w.Storage, w); ret.Client == nil {
		return nil
	}

	// set redirect uri
	ret.RedirectURI = FirstURI(ret.Client.GetRedirectURI(), s.cfg.RedirectURISeparator)

	return ret
}

func (s *Server) FinishAccessRequest(w *Response, r *http.Request, ar *AccessRequest) {
	// don't process if is already an error
	if w.IsError {
		return
	}

	redirectUri := r.FormValue("redirect_uri")

	// Get redirect uri from AccessRequest if it's there (e.g., refresh token request)
	if ar.RedirectURI != "" {
		redirectUri = ar.RedirectURI
	}

	if !ar.Authorized {
		s.setErrorAndLog(w, E_ACCESS_DENIED, nil, "finish_access_request=%s", "authorization failed")

		return
	}

	var ret *AccessData

	var err error

	if ar.ForceAccessData == nil {
		// generate access token
		ret = &AccessData{
			Client:        ar.Client,
			AuthorizeData: ar.AuthorizeData,
			AccessData:    ar.AccessData,
			RedirectURI:   redirectUri,
			CreatedAt:     s.now(),
			ExpiresIn:     int64(ar.Expiration.Seconds()),
			UserData:      ar.UserData,
			Scope:         ar.Scope,
		}

		// generate access token
		// @TODO: add ret at first arg for GenerateAccessToken
		ret.AccessToken, ret.RefreshToken, err = s.tokenGenerator.GenerateAccessToken(ar.GenerateRefresh)
		if err != nil {
			s.setErrorAndLog(w, E_SERVER_ERROR, err, "finish_access_request=%s", "error generating token")

			return
		}
	} else {
		ret = ar.ForceAccessData
	}

	// save access token
	if err = w.Storage.SaveAccess(ret); err != nil {
		s.setErrorAndLog(w, E_SERVER_ERROR, err, "finish_access_request=%s", "error saving access token")

		return
	}

	// remove authorization token
	if ret.AuthorizeData != nil {
		if err := w.Storage.RemoveAuthorize(ret.AuthorizeData.Code); err != nil {
			s.logger.Error("oauth2: remove autorize code failed", logger.WithLabels(map[string]interface{}{
				"code": ret.AuthorizeData.Code,
			}))
		}
	}

	// remove previous access token
	if ret.AccessData != nil && !s.cfg.RetainTokenAfterRefresh {
		if ret.AccessData.RefreshToken != "" {
			if err := w.Storage.RemoveRefresh(ret.AccessData.RefreshToken); err != nil {
				s.logger.Error("oauth2: remove refresh token failed", logger.WithLabels(map[string]interface{}{
					"refresh_token": ret.AccessData.RefreshToken,
				}))
			}
		}

		if err := w.Storage.RemoveAccess(ret.AccessData.AccessToken); err != nil {
			s.logger.Error("oauth2: remove access token failed", logger.WithLabels(map[string]interface{}{
				"access_token": ret.AccessData.AccessToken,
			}))
		}
	}

	// output data
	w.Output["access_token"] = ret.AccessToken
	w.Output["token_type"] = s.cfg.TokenType
	w.Output["expires_in"] = ret.ExpiresIn

	if ret.RefreshToken != "" {
		w.Output["refresh_token"] = ret.RefreshToken
	}

	if ret.Scope != "" {
		w.Output["scope"] = ret.Scope
	}
}

// Helper Functions

// getClient looks up and authenticates the basic auth using the given
// storage. Sets an error on the response if auth fails or a server error occurs.
func (s Server) getClient(creds *credential.UsernamePasswordCredential, storage StorageProvider, w *Response) Client {
	client, err := storage.LoadClient(creds.GetPrincipal().(string))
	if errors.Is(err, ErrClientNotFound) {
		s.setErrorAndLog(w, E_UNAUTHORIZED_CLIENT, nil, "get_client=%s", "not found")

		return nil
	}

	if err != nil {
		s.setErrorAndLog(w, E_SERVER_ERROR, err, "get_client=%s", "error finding client")

		return nil
	}

	if client == nil {
		s.setErrorAndLog(w, E_UNAUTHORIZED_CLIENT, nil, "get_client=%s", "client is nil")

		return nil
	}

	if !CheckClientSecret(client, creds.GetCredentials().(string)) {
		s.setErrorAndLog(w, E_UNAUTHORIZED_CLIENT, nil, "get_client=%s, client_id=%v", "client check failed", client.GetID())

		return nil
	}

	if client.GetRedirectURI() == "" {
		s.setErrorAndLog(w, E_UNAUTHORIZED_CLIENT, nil, "get_client=%s", "client redirect uri is empty")

		return nil
	}

	return client
}

// setErrorAndLog sets the response error and internal error (if non-nil) and logs them along with the provided debug format string and arguments.
func (s Server) setErrorAndLog(w *Response, responseError DefaultErrorID, internalError error, debugFormat string, debugArgs ...interface{}) {
	format := "error=%v, internal_error=%#v " + debugFormat

	w.InternalError = internalError
	w.SetError(responseError, "")

	s.logger.Error(
		format,
		logger.WithFormat(append([]interface{}{responseError, internalError}, debugArgs...)...),
	)
}
