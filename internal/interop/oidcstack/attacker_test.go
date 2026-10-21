// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcstack_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
)

// attackerAS is an authorization server the attacker controls — a tenant
// of a broker configuring its own identity provider, say — with
// genuine-looking discovery. Its authorization endpoint sends the user
// agent on to the honest provider with the request rewritten by divert;
// its token endpoint records every code it receives (RFC 9700 §4.4.1).
type attackerAS struct {
	srv *httptest.Server

	mu     sync.Mutex
	divert func(q url.Values) string // the honest authorization URL to send the user agent to
	codes  []string                  // codes the token endpoint received
}

func newAttackerAS(t *testing.T, divert func(q url.Values) string) *attackerAS {
	t.Helper()

	return newAttackerASAdvertising(t, false, divert)
}

// newAttackerASAdvertising is newAttackerAS whose metadata advertises RFC
// 9207 (authorization_response_iss_parameter_supported) when iss is true.
func newAttackerASAdvertising(t *testing.T, iss bool, divert func(q url.Values) string) *attackerAS {
	t.Helper()

	a := &attackerAS{divert: divert}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		doc := map[string]any{
			"issuer": a.srv.URL, "authorization_endpoint": a.srv.URL + "/authorize",
			"token_endpoint": a.srv.URL + "/token", "jwks_uri": a.srv.URL + "/jwks",
			"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"code_challenge_methods_supported":      []string{"S256"},
		}

		if iss {
			doc["authorization_response_iss_parameter_supported"] = true
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, a.divert(r.URL.Query()), http.StatusSeeOther)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()

		a.mu.Lock()
		a.codes = append(a.codes, r.PostForm.Get("code"))
		a.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	})

	a.srv = httptest.NewUnstartedServer(mux)
	a.srv.StartTLS()
	t.Cleanup(a.srv.Close)

	return a
}

// received returns the codes the attacker's token endpoint received.
func (a *attackerAS) received() []string {
	a.mu.Lock()
	defer a.mu.Unlock()

	return append([]string(nil), a.codes...)
}
