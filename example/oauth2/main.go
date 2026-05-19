// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package main demonstrates wiring of the security library with an OAuth2
// client-credentials flow over plain net/http.
//
// Run:
//
//	go run ./example/oauth2
//
// Probe (replace credentials if you change main()):
//
//	curl -i http://localhost:1337/                 # public
//	curl -i -u 5cc06c3b-5755-4229-958c-a515a245aaeb:WTvuAztPD2XBauomleRzGFYuZawS07Ym \
//	    http://localhost:1337/protected            # private
package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gilcrest/alice"
	"github.com/hyperscale-stack/security/authentication"
	"github.com/hyperscale-stack/security/authentication/provider/oauth2"
	"github.com/hyperscale-stack/security/authentication/provider/oauth2/storage"
	"github.com/hyperscale-stack/security/authentication/provider/oauth2/token/random"
	"github.com/hyperscale-stack/security/authorization"
	"github.com/hyperscale-stack/security/user"
)

// noopUserProvider is sufficient for a pure client_credentials demo: only the
// access-token grant path queries it, and we never issue access tokens here.
type noopUserProvider struct{}

func (noopUserProvider) LoadUser(string) (user.User, error) {
	return nil, oauth2.ErrUserNotFound
}

// Demo credentials. Hard-coded for the example; in real usage these come from
// a client store seeded out-of-band.
const (
	demoClientID     = "5cc06c3b-5755-4229-958c-a515a245aaeb"
	demoClientSecret = "WTvuAztPD2XBauomleRzGFYuZawS07Ym" //nolint:gosec // demo
)

func main() {
	tokenGenerator := random.NewTokenGenerator(&random.Configuration{})

	storageProvider := storage.NewInMemoryStorage()

	if err := storageProvider.SaveClient(&oauth2.DefaultClient{
		ID:          demoClientID,
		Secret:      demoClientSecret,
		RedirectURI: "https://connect.myservice.tld",
	}); err != nil {
		log.Fatalf("seed client: %v", err)
	}

	// userStorageProvider is queried by the access-token grant path. A noop
	// implementation is fine for this client_credentials demo, where access
	// tokens are not issued.
	userStorageProvider := noopUserProvider{}

	authChain := alice.New(
		authentication.FilterHandler(
			authentication.NewBearerFilter(),
			authentication.NewAccessTokenFilter(),
			authentication.NewHTTPBasicFilter(),
		),
		authentication.Handler(
			oauth2.NewOAuth2AuthenticationProvider(
				tokenGenerator,
				userStorageProvider,
				storageProvider, // ClientProvider
				storageProvider, // AccessProvider
				storageProvider, // RefreshProvider
				storageProvider, // AuthorizeProvider
			),
		),
	)

	private := authChain.Append(authorization.AuthorizeHandler())

	mux := http.NewServeMux()

	mux.Handle("GET /protected", private.ThenFunc(func(w http.ResponseWriter, r *http.Request) {
		client := oauth2.ClientFromContext(r.Context())
		if client == nil {
			http.Error(w, "no client in context", http.StatusInternalServerError)

			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		// client.GetID is server-controlled (loaded from the in-memory client
		// store, not from user input), so reflecting it back is safe in this
		// demo context. The taint analyzer cannot prove this and flags G705.
		_, _ = fmt.Fprintf(w, "hello %s\n", client.GetID()) //nolint:gosec // demo
	}))

	mux.HandleFunc("GET /", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("public\n"))
	})

	addr := ":1337"
	log.Printf("listening on %s", addr)

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
