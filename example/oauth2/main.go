// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	"net/http"

	"github.com/gilcrest/alice"
	"github.com/gorilla/mux"
	"github.com/hyperscale-stack/security/authentication"
	"github.com/hyperscale-stack/security/authentication/provider/oauth2"
	"github.com/hyperscale-stack/security/authentication/provider/oauth2/storage"
	"github.com/hyperscale-stack/security/authentication/provider/oauth2/token/random"
	"github.com/hyperscale-stack/security/authorization"
)

func main() {
	r := mux.NewRouter()

	tokenGenerator := random.NewTokenGenerator(&random.Configuration{})

	storageProvider := storage.NewInMemoryStorage()

	storageProvider.SaveClient(&oauth2.DefaultClient{
		ID:          "5cc06c3b-5755-4229-958c-a515a245aaeb",
		Secret:      "WTvuAztPD2XBauomleRzGFYuZawS07Ym",
		RedirectURI: "https://connect.myservice.tld",
	})

	// Add authentication filters
	r.Use(authentication.FilterHandler(
		authentication.NewBearerFilter(),
		authentication.NewAccessTokenFilter(),
		authentication.NewHTTPBasicFilter(),
	))

	// Add authentication handler
	r.Use(authentication.Handler(
		oauth2.NewOAuth2AuthenticationProvider(tokenGenerator, storageProvider),
	))

	private := alice.New(
		authorization.AuthorizeHandler(),
	)

	r.Handle("/protected", private.ThenFunc(func(w http.ResponseWriter, r *http.Request) {
		// private route
	})).Methods(http.MethodGet)

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// public route
	}).Methods(http.MethodGet)

	if err := http.ListenAndServe(":1337", r); err != nil {
		panic(err)
	}
}
