// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grant_test

import (
	"net/url"
	"testing"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuthorizationCodeBurnedByAFailedExchange pins a documented design
// choice (see the AuthorizationCode godoc): a code is consumed before it is
// validated. A party holding the code — presenting a wrong verifier, or
// authenticated as another client — obtains nothing, but burns the code:
// the legitimate exchange that follows is refused too, and nothing is
// issued to anyone.
func TestAuthorizationCodeBurnedByAFailedExchange(t *testing.T) {
	t.Parallel()

	attacks := map[string]func(grant.Request) grant.Request{
		"a wrong verifier": withForm(func(f url.Values) { f.Set("code_verifier", wellFormedWrongVerifier) }),
		"another client": func(req grant.Request) grant.Request {
			req.Client = &oauth2.DefaultClient{
				IDValue: "attacker", TypeValue: oauth2.ClientConfidential, GrantTypeValues: allGrantTypes,
			}

			return req
		},
	}

	for name, attack := range attacks {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			store := &replayStore{Store: memory.New()}
			g := grant.NewAuthorizationCode(rotatingConfig(store, &hookRecorder{}))
			req := codeRequest(t, store, "burned-code")

			resp, err := g.Handle(t.Context(), attack(req))
			require.Error(t, err)
			assert.Nil(t, resp)
			assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))

			resp, err = g.Handle(t.Context(), req)
			assert.Nil(t, resp)
			require.ErrorIs(t, err, oauth2.ErrCodeAlreadyUsed, "the legitimate exchange fails closed")
			assert.Empty(t, store.savedPairs(), "nothing issued to anyone")
		})
	}
}
