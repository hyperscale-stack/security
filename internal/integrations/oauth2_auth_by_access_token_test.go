// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package integrations

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gilcrest/alice"
	"github.com/hyperscale-stack/security/authentication"
	"github.com/hyperscale-stack/security/authentication/credential"
	"github.com/hyperscale-stack/security/authentication/provider/oauth2"
	"github.com/hyperscale-stack/security/authentication/provider/oauth2/storage"
	"github.com/hyperscale-stack/security/authentication/provider/oauth2/token/random"
	"github.com/hyperscale-stack/security/authorization"
	"github.com/hyperscale-stack/security/user"
	"github.com/stretchr/testify/assert"
)

func TestOauth2AuthByAccessTokenWithNoAuthHeader(t *testing.T) {
	tokenGenerator := random.NewTokenGenerator(&random.Configuration{})

	userProvider := &oauth2.MockUserProvider{}

	storageProvider := storage.NewInMemoryStorage()

	client := &oauth2.DefaultClient{
		ID:          "5cc06c3b-5755-4229-958c-a515a245aaeb",
		Secret:      "WTvuAztPD2XBauomleRzGFYuZawS07Ym",
		RedirectURI: "https://connect.myservice.tld",
	}

	storageProvider.SaveClient(client)

	storageProvider.SaveAccess(&oauth2.AccessData{
		Client:      client,
		AccessToken: "I3SoKTVXi6QzMZAmDW2Fgw2MLX0msPGRN58bCDLDFthJmy6Qoy8FH5v10dbewR6PfAV3brKhepjnTJVhDplSHFe6qbF3J4YDkI5EzXG0S8X7snSoB6FtrPNFMmISuEmU",
		UserData:    "8c87a032-755d-42f6-be96-0421948f6e94",
	})

	private := alice.New(
		authentication.FilterHandler(
			authentication.NewAccessTokenFilter(),
		),
		authentication.Handler(
			oauth2.NewOAuth2AuthenticationProvider(tokenGenerator, userProvider, storageProvider, storageProvider, storageProvider, storageProvider),
		),
		authorization.AuthorizeHandler(),
	)

	handler := private.ThenFunc(func(w http.ResponseWriter, r *http.Request) {
		// private route
	})

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	userProvider.AssertNotCalled(t, "LoadUser")
}

func TestOauth2AuthByAccessTokenWithBadToken(t *testing.T) {
	tokenGenerator := random.NewTokenGenerator(&random.Configuration{})

	userProvider := &oauth2.MockUserProvider{}

	storageProvider := storage.NewInMemoryStorage()

	client := &oauth2.DefaultClient{
		ID:          "5cc06c3b-5755-4229-958c-a515a245aaeb",
		Secret:      "WTvuAztPD2XBauomleRzGFYuZawS07Ym",
		RedirectURI: "https://connect.myservice.tld",
	}

	storageProvider.SaveClient(client)

	storageProvider.SaveAccess(&oauth2.AccessData{
		Client:      client,
		AccessToken: "I3SoKTVXi6QzMZAmDW2Fgw2MLX0msPGRN58bCDLDFthJmy6Qoy8FH5v10dbewR6PfAV3brKhepjnTJVhDplSHFe6qbF3J4YDkI5EzXG0S8X7snSoB6FtrPNFMmISuEmU",
	})

	private := alice.New(
		authentication.FilterHandler(
			authentication.NewBearerFilter(),
			authentication.NewAccessTokenFilter(),
			authentication.NewHTTPBasicFilter(),
		),
		authentication.Handler(
			oauth2.NewOAuth2AuthenticationProvider(tokenGenerator, userProvider, storageProvider, storageProvider, storageProvider, storageProvider),
		),
		authorization.AuthorizeHandler(),
	)

	handler := private.ThenFunc(func(w http.ResponseWriter, r *http.Request) {
		// private route
	})

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	req.Header.Set("Authorization", "Bearer bad")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestOauth2AuthByAccessToken(t *testing.T) {
	tokenGenerator := random.NewTokenGenerator(&random.Configuration{})

	userMock := &user.MockUser{}

	userMock.On("GetRoles").Return([]string{"ROLE_USER"})
	userMock.On("GetUsername").Return("euskadi31")

	userProvider := &oauth2.MockUserProvider{}

	userProvider.On("LoadUser", "8c87a032-755d-42f6-be96-0421948f6e94").Return(userMock, nil)

	storageProvider := storage.NewInMemoryStorage()

	client := &oauth2.DefaultClient{
		ID:          "5cc06c3b-5755-4229-958c-a515a245aaeb",
		Secret:      "WTvuAztPD2XBauomleRzGFYuZawS07Ym",
		RedirectURI: "https://connect.myservice.tld",
	}

	storageProvider.SaveClient(client)

	storageProvider.SaveAccess(&oauth2.AccessData{
		Client:      client,
		AccessToken: "I3SoKTVXi6QzMZAmDW2Fgw2MLX0msPGRN58bCDLDFthJmy6Qoy8FH5v10dbewR6PfAV3brKhepjnTJVhDplSHFe6qbF3J4YDkI5EzXG0S8X7snSoB6FtrPNFMmISuEmU",
		ExpiresIn:   60,
		CreatedAt:   time.Now(),
		UserData:    "8c87a032-755d-42f6-be96-0421948f6e94",
	})

	private := alice.New(
		authentication.FilterHandler(
			authentication.NewBearerFilter(),
			authentication.NewAccessTokenFilter(),
			authentication.NewHTTPBasicFilter(),
		),
		authentication.Handler(
			oauth2.NewOAuth2AuthenticationProvider(tokenGenerator, userProvider, storageProvider, storageProvider, storageProvider, storageProvider),
		),
		authorization.AuthorizeHandler(),
	)

	handler := private.ThenFunc(func(w http.ResponseWriter, r *http.Request) {
		// private route

		ctx := r.Context()

		token := oauth2.AccessTokenFromContext(ctx)
		assert.NotNil(t, token)

		user := credential.FromContext(ctx)
		assert.NotNil(t, user)

		assert.Equal(t, "euskadi31", user.GetUser().GetUsername())
		assert.Equal(t, []string{"ROLE_USER"}, user.GetUser().GetRoles())

		err := json.NewEncoder(w).Encode(token)
		assert.NoError(t, err)
	})

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	req.Header.Set("Authorization", "Bearer I3SoKTVXi6QzMZAmDW2Fgw2MLX0msPGRN58bCDLDFthJmy6Qoy8FH5v10dbewR6PfAV3brKhepjnTJVhDplSHFe6qbF3J4YDkI5EzXG0S8X7snSoB6FtrPNFMmISuEmU")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()

	token := struct {
		Client struct {
			ID     string
			Secret string
		}
		AccessToken string
	}{}

	err := json.NewDecoder(resp.Body).Decode(&token)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	assert.Equal(t, "I3SoKTVXi6QzMZAmDW2Fgw2MLX0msPGRN58bCDLDFthJmy6Qoy8FH5v10dbewR6PfAV3brKhepjnTJVhDplSHFe6qbF3J4YDkI5EzXG0S8X7snSoB6FtrPNFMmISuEmU", token.AccessToken)

	assert.Equal(t, "5cc06c3b-5755-4229-958c-a515a245aaeb", token.Client.ID)
	assert.Equal(t, "WTvuAztPD2XBauomleRzGFYuZawS07Ym", token.Client.Secret)

	userProvider.AssertExpectations(t)
	userMock.AssertExpectations(t)
}
