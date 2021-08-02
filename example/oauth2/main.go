package main

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/hyperscale-stack/security/authentication"
	"github.com/hyperscale-stack/security/authentication/provider/oauth2"
	"github.com/hyperscale-stack/security/authentication/provider/oauth2/token/random"
)

func main() {
	r := mux.NewRouter()

	tokenGenerator := random.NewTokenGenerator(&random.Configuration{})

	storageProvider := NewOAuth2Storage()

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

	r.

	if err := http.ListenAndServe(":1337", r); err != nil {
		panic(err)
	}
}
