// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// consenting is a ConsentFunc approving as alice with scope as
// Consent.Scope.
func consenting(scope string) oauth2.ConsentFunc {
	return func(http.ResponseWriter, *http.Request, *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
		return &oauth2.Consent{Approved: true, Subject: "alice", Scope: scope}, nil
	}
}

// TestConsentCannotBroadenTheRequest pins the Consent.Scope contract and RFC
// 6749 §3.3: the consent step narrows the requested scope, never broadens
// it — not even a request without scope, whose grant it could otherwise
// fill with any scope, registered for the client or not. The request is
// already a subset of the client's registration, so a grant never exceeds
// request ∩ registration. A consent naming no scope — empty, or SPs only —
// grants exactly what was requested.
func TestConsentCannotBroadenTheRequest(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, requested, consented string
		want                       string // the granted scope; "" with refused
		refused                    bool
	}{
		{"empty request, scopes outside the registration", "", "admin delete-everything", "", true},
		{"empty request, a registered scope", "", "read", "", true},
		{"a scope outside the request", "read", "read write", "", true},
		{"a malformed consent scope", "read write", "read\twrite", "", true},
		{"narrowed", "read write", "read", "read", false},
		{"narrowed, repetitions dropped", "read write", "write  write", "write", false},
		{"no consent scope", "read write", "", "read write", false},
		{"a blank consent scope", "read write", "   ", "read write", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &writeCountingStore{Store: memory.New()}
			env := newExtensionEnv(t, &fakeExtension{}, withStore(store))

			q := authorizeQuery()
			q.Set("scope", tc.requested)

			rec := env.authorize(q, consenting(tc.consented))
			require.Equal(t, http.StatusFound, rec.Code)

			params := mustLocation(t, rec).Query()
			if tc.refused {
				assert.Equal(t, oauth2.CodeInvalidScope, params.Get("error"))
				assert.Empty(t, params.Get("code"))
				assert.Zero(t, store.writes.Load(), "nothing persisted")

				return
			}

			tokens := env.exchange(params.Get("code"))
			require.Equal(t, http.StatusOK, tokens.Code, tokens.Body.String())
			assert.Equal(t, tc.want, jsonBody(t, tokens)["scope"])
		})
	}
}

// TestImplicitConsentCannotBroadenTheRequest: the implicit flow applies the
// same rule; its refusal travels in the fragment.
func TestImplicitConsentCannotBroadenTheRequest(t *testing.T) {
	t.Parallel()

	store := &writeCountingStore{Store: memory.New()}
	env := newExtensionEnv(t, &fakeExtension{}, withStore(store), withProfile(oauth2.Profile20))

	q := implicitQuery()
	q.Del("scope")

	rec := runAuthorizeCfg(env.srv, oauth2.AuthorizeConfig{AllowImplicit: true, ImplicitTokens: implicitTokens()},
		q, consenting("admin"))
	require.Equal(t, http.StatusFound, rec.Code)

	frag, err := url.ParseQuery(mustLocation(t, rec).Fragment)
	require.NoError(t, err)
	assert.Equal(t, oauth2.CodeInvalidScope, frag.Get("error"))
	assert.Empty(t, frag.Get("access_token"))
	assert.Zero(t, store.writes.Load(), "nothing persisted")
}
