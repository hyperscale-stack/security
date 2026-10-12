// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grant_test

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClientCredentialsRefusesNonConfidentialClients pins RFC 6749 §4.4 in
// the grant itself, for a direct call or a decorated grant: a public or an
// untyped client gets unauthorized_client, nothing is persisted.
func TestClientCredentialsRefusesNonConfidentialClients(t *testing.T) {
	t.Parallel()

	for name, typ := range map[string]oauth2.ClientType{"public": oauth2.ClientPublic, "untyped": ""} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			store := &replayStore{Store: newStore()}
			g := grant.NewClientCredentials(grant.Config{Storage: store, AccessTokens: newAccessGen(), AccessTTL: time.Hour})

			client := &oauth2.DefaultClient{
				IDValue: clientID, TypeValue: typ,
				GrantTypeValues: []string{oauth2.GrantTypeClientCredentials}, ScopeValues: []string{"read:mail"},
			}

			resp, err := g.Handle(context.Background(), grant.Request{Client: client, Form: url.Values{}, Now: time.Now()})
			require.Error(t, err)
			assert.Nil(t, resp)
			assert.Equal(t, oauth2.CodeUnauthorizedClient, oauth2.IsCode(err))
			assert.Empty(t, store.savedPairs())
		})
	}
}
