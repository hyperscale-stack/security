// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package integrations

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gilcrest/alice"
	"github.com/hyperscale-stack/security/authentication"
	"github.com/hyperscale-stack/security/authentication/provider/oauth2"
	"github.com/hyperscale-stack/security/authentication/provider/oauth2/storage"
	"github.com/hyperscale-stack/security/authentication/provider/oauth2/token/random"
	"github.com/hyperscale-stack/security/authorization"
	"github.com/stretchr/testify/assert"
)

func TestOauth2AuthByClientWithNoAuthHeader(t *testing.T) {
	tokenGenerator := random.NewTokenGenerator(&random.Configuration{})

	storageProvider := storage.NewInMemoryStorage()

	storageProvider.SaveClient(&oauth2.DefaultClient{
		ID:          "5cc06c3b-5755-4229-958c-a515a245aaeb",
		Secret:      "WTvuAztPD2XBauomleRzGFYuZawS07Ym",
		RedirectURI: "https://connect.myservice.tld",
	})

	private := alice.New(
		authentication.FilterHandler(
			authentication.NewHTTPBasicFilter(),
		),
		authentication.Handler(
			oauth2.NewOAuth2AuthenticationProvider(tokenGenerator, storageProvider),
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
}

func TestOauth2AuthByClientWithBadClientID(t *testing.T) {
	tokenGenerator := random.NewTokenGenerator(&random.Configuration{})

	storageProvider := storage.NewInMemoryStorage()

	storageProvider.SaveClient(&oauth2.DefaultClient{
		ID:          "5cc06c3b-5755-4229-958c-a515a245aaeb",
		Secret:      "WTvuAztPD2XBauomleRzGFYuZawS07Ym",
		RedirectURI: "https://connect.myservice.tld",
	})

	private := alice.New(
		authentication.FilterHandler(
			authentication.NewBearerFilter(),
			authentication.NewAccessTokenFilter(),
			authentication.NewHTTPBasicFilter(),
		),
		authentication.Handler(
			oauth2.NewOAuth2AuthenticationProvider(tokenGenerator, storageProvider),
		),
		authorization.AuthorizeHandler(),
	)

	handler := private.ThenFunc(func(w http.ResponseWriter, r *http.Request) {
		// private route
	})

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	req.SetBasicAuth("bad", "foo")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestOauth2AuthByClientWithBadPassword(t *testing.T) {
	tokenGenerator := random.NewTokenGenerator(&random.Configuration{})

	storageProvider := storage.NewInMemoryStorage()

	storageProvider.SaveClient(&oauth2.DefaultClient{
		ID:          "5cc06c3b-5755-4229-958c-a515a245aaeb",
		Secret:      "WTvuAztPD2XBauomleRzGFYuZawS07Ym",
		RedirectURI: "https://connect.myservice.tld",
	})

	private := alice.New(
		authentication.FilterHandler(
			authentication.NewBearerFilter(),
			authentication.NewAccessTokenFilter(),
			authentication.NewHTTPBasicFilter(),
		),
		authentication.Handler(
			oauth2.NewOAuth2AuthenticationProvider(tokenGenerator, storageProvider),
		),
		authorization.AuthorizeHandler(),
	)

	handler := private.ThenFunc(func(w http.ResponseWriter, r *http.Request) {
		// private route
	})

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	req.SetBasicAuth("5cc06c3b-5755-4229-958c-a515a245aaeb", "bad")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestOauth2AuthByClient(t *testing.T) {
	tokenGenerator := random.NewTokenGenerator(&random.Configuration{})

	storageProvider := storage.NewInMemoryStorage()

	storageProvider.SaveClient(&oauth2.DefaultClient{
		ID:          "5cc06c3b-5755-4229-958c-a515a245aaeb",
		Secret:      "WTvuAztPD2XBauomleRzGFYuZawS07Ym",
		RedirectURI: "https://connect.myservice.tld",
	})

	private := alice.New(
		authentication.FilterHandler(
			authentication.NewBearerFilter(),
			authentication.NewAccessTokenFilter(),
			authentication.NewHTTPBasicFilter(),
		),
		authentication.Handler(
			oauth2.NewOAuth2AuthenticationProvider(tokenGenerator, storageProvider),
		),
		authorization.AuthorizeHandler(),
	)

	handler := private.ThenFunc(func(w http.ResponseWriter, r *http.Request) {
		// private route
	})

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	req.SetBasicAuth("5cc06c3b-5755-4229-958c-a515a245aaeb", "WTvuAztPD2XBauomleRzGFYuZawS07Ym")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
