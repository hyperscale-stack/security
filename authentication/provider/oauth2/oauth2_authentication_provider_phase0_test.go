// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"net/http/httptest"
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/authentication/credential"
	"github.com/hyperscale-stack/security/authentication/provider/oauth2/token/random"
	"github.com/stretchr/testify/assert"
)

// TestOAuth2AuthenticateByClientSecretMismatch locks the Phase 0 fix: the
// previous implementation kept the credential unauthenticated and returned a
// nil error when the supplied client secret did not match the stored one,
// relying on a downstream AuthorizeHandler to reject the request. The fix
// surfaces the failure as security.ErrClientSecretMismatch.
func TestOAuth2AuthenticateByClientSecretMismatch(t *testing.T) {
	t.Parallel()

	tokenGenerator := random.NewTokenGenerator(&random.Configuration{})

	clientStorageMock := &MockClientProvider{}

	stored := &DefaultClient{
		ID:          "client-1",
		Secret:      "correct-horse-battery-staple",
		RedirectURI: "https://example.com/cb",
	}

	clientStorageMock.On("LoadClient", "client-1").Return(stored, nil).Once()

	p := NewOAuth2AuthenticationProvider(tokenGenerator, nil, clientStorageMock, nil, nil, nil)

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	creds := credential.NewUsernamePasswordCredential("client-1", "wrong-secret")

	r, err := p.Authenticate(req, creds)

	assert.ErrorIs(t, err, security.ErrClientSecretMismatch)
	assert.False(t, creds.IsAuthenticated(),
		"credential must remain unauthenticated on secret mismatch")
	// On error the provider returns the original request unchanged.
	assert.Same(t, req, r)

	clientStorageMock.AssertExpectations(t)
}

// nonMatcherClient implements oauth2.Client but NOT ClientSecretMatcher. This
// previously slipped through with a nil error and an unauthenticated
// credential; Phase 0 turns it into an explicit ErrClientSecretMismatch.
type nonMatcherClient struct {
	id, secret, redirect string
}

func (c *nonMatcherClient) GetID() string          { return c.id }
func (c *nonMatcherClient) GetSecret() string      { return c.secret }
func (c *nonMatcherClient) GetRedirectURI() string { return c.redirect }
func (c *nonMatcherClient) GetUserData() any       { return nil }

func TestOAuth2AuthenticateByClientWithoutSecretMatcher(t *testing.T) {
	t.Parallel()

	tokenGenerator := random.NewTokenGenerator(&random.Configuration{})

	clientStorageMock := &MockClientProvider{}

	stored := &nonMatcherClient{id: "client-2", secret: "x", redirect: "https://x"}
	clientStorageMock.On("LoadClient", "client-2").Return(stored, nil).Once()

	p := NewOAuth2AuthenticationProvider(tokenGenerator, nil, clientStorageMock, nil, nil, nil)

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	creds := credential.NewUsernamePasswordCredential("client-2", "x")

	r, err := p.Authenticate(req, creds)

	assert.ErrorIs(t, err, security.ErrClientSecretMismatch)
	assert.False(t, creds.IsAuthenticated())
	assert.Same(t, req, r)

	clientStorageMock.AssertExpectations(t)
}
