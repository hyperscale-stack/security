// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/oauth2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrorError(t *testing.T) {
	t.Parallel()

	withDesc := &oauth2.Error{Code: oauth2.CodeInvalidGrant, Description: "expired"}
	assert.Equal(t, "oauth2: invalid_grant: expired", withDesc.Error())

	bare := &oauth2.Error{Code: oauth2.CodeInvalidGrant}
	assert.Equal(t, "oauth2: invalid_grant", bare.Error())
}

func TestErrorUnwrapAndIs(t *testing.T) {
	t.Parallel()

	// The sentinels wrap a core security sentinel via the cause chain.
	assert.ErrorIs(t, oauth2.ErrInvalidClient, security.ErrClientSecretMismatch)
	assert.ErrorIs(t, oauth2.ErrInvalidGrant, security.ErrInvalidCredentials)
	assert.ErrorIs(t, oauth2.ErrUnsupportedGrantType, security.ErrUnsupportedCredential)
	assert.ErrorIs(t, oauth2.ErrAccessDenied, security.ErrAccessDenied)

	// ErrServerError has a nil cause: Unwrap returns nil, no panic.
	assert.NoError(t, oauth2.ErrServerError.Unwrap())
}

func TestErrorHTTPStatus(t *testing.T) {
	t.Parallel()

	cases := []struct {
		code string
		want int
	}{
		{oauth2.CodeInvalidClient, http.StatusUnauthorized},
		{oauth2.CodeAccessDenied, http.StatusForbidden},
		{oauth2.CodeServerError, http.StatusInternalServerError},
		{oauth2.CodeTemporarilyUnavailable, http.StatusServiceUnavailable},
		{oauth2.CodeInvalidRequest, http.StatusBadRequest},
		{oauth2.CodeInvalidGrant, http.StatusBadRequest},
	}

	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, (&oauth2.Error{Code: tc.code}).HTTPStatus())
		})
	}
}

func TestIsCode(t *testing.T) {
	t.Parallel()

	assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(oauth2.ErrInvalidGrant))
	assert.Equal(t, oauth2.CodeInvalidGrant,
		oauth2.IsCode(fmt.Errorf("wrapped: %w", oauth2.ErrInvalidGrant)))
	assert.Empty(t, oauth2.IsCode(errors.New("not an oauth2 error")))
	assert.Empty(t, oauth2.IsCode(nil))
}

func TestErrorWithDescription(t *testing.T) {
	t.Parallel()

	got := oauth2.ErrInvalidGrant.WithDescription("code expired")
	assert.Equal(t, "code expired", got.Description)
	assert.Equal(t, oauth2.CodeInvalidGrant, got.Code)
	// The sentinel stays immutable.
	assert.NotEqual(t, "code expired", oauth2.ErrInvalidGrant.Description)
}

func TestErrorWithCause(t *testing.T) {
	t.Parallel()

	root := errors.New("disk on fire")
	got := oauth2.ErrServerError.WithCause(root)

	assert.ErrorIs(t, got, root)
	assert.Equal(t, oauth2.CodeServerError, got.Code)
	// Original sentinel untouched.
	assert.NotErrorIs(t, oauth2.ErrServerError, root)

	// WithCause on a sentinel that already has a cause keeps both reachable.
	chained := oauth2.ErrInvalidGrant.WithCause(root)
	assert.ErrorIs(t, chained, root)
	assert.ErrorIs(t, chained, security.ErrInvalidCredentials)
}

func TestProfileString(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "oauth2.0-bcp", oauth2.Profile20BCP.String())
	assert.Equal(t, "oauth2.0", oauth2.Profile20.String())
	assert.Equal(t, "oauth2.1-draft", oauth2.Profile21Draft.String())
	assert.Equal(t, "unknown", oauth2.Profile(99).String())
}

func TestProfilePredicates(t *testing.T) {
	t.Parallel()

	cases := []struct {
		profile                                        oauth2.Profile
		legacy, pkce, rotation, plainPKCE              bool
	}{
		{oauth2.Profile20, true, false, false, true},
		{oauth2.Profile20BCP, false, true, true, false},
		{oauth2.Profile21Draft, false, true, true, false},
	}

	for _, tc := range cases {
		t.Run(tc.profile.String(), func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.legacy, tc.profile.AllowsLegacyGrant())
			assert.Equal(t, tc.pkce, tc.profile.RequiresPKCE())
			assert.Equal(t, tc.rotation, tc.profile.RequiresRefreshRotation())
			assert.Equal(t, tc.plainPKCE, tc.profile.AllowsPKCEPlain())
		})
	}
}

func TestModelsIsExpired(t *testing.T) {
	t.Parallel()

	now := time.Now()
	past := now.Add(-time.Minute)
	future := now.Add(time.Minute)

	code := &oauth2.AuthorizationCode{ExpiresAt: past}
	assert.True(t, code.IsExpired(now))
	assert.False(t, (&oauth2.AuthorizationCode{ExpiresAt: future}).IsExpired(now))

	at := &oauth2.AccessToken{ExpiresAt: past}
	assert.True(t, at.IsExpired(now))
	assert.False(t, (&oauth2.AccessToken{ExpiresAt: future}).IsExpired(now))

	rt := &oauth2.RefreshToken{ExpiresAt: past}
	assert.True(t, rt.IsExpired(now))
	assert.False(t, (&oauth2.RefreshToken{ExpiresAt: future}).IsExpired(now))
}

func TestHashToken(t *testing.T) {
	t.Parallel()

	pepper := []byte("server-wide-secret")

	// Deterministic for the same (pepper, token).
	assert.Equal(t, oauth2.HashToken(pepper, "tok"), oauth2.HashToken(pepper, "tok"))
	// Different token -> different hash.
	assert.NotEqual(t, oauth2.HashToken(pepper, "tok"), oauth2.HashToken(pepper, "other"))
	// Different pepper -> different hash.
	assert.NotEqual(t, oauth2.HashToken(pepper, "tok"), oauth2.HashToken([]byte("x"), "tok"))
	// SHA-256 HMAC hex output is 64 characters.
	assert.Len(t, oauth2.HashToken(pepper, "tok"), 64)
}

func TestDefaultClient(t *testing.T) {
	t.Parallel()

	c := &oauth2.DefaultClient{
		IDValue:           "client-1",
		Secret:            "s3cr3t",
		TypeValue:         oauth2.ClientConfidential,
		RedirectURIValues: []string{"https://app.example/cb"},
		GrantTypeValues:   []string{"authorization_code"},
		ScopeValues:       []string{"read"},
		AuthMethodValues:  []string{"client_secret_basic"},
	}

	assert.Equal(t, "client-1", c.ID())
	assert.Equal(t, oauth2.ClientConfidential, c.Type())
	assert.Equal(t, []string{"https://app.example/cb"}, c.RedirectURIs())
	assert.Equal(t, []string{"authorization_code"}, c.GrantTypes())
	assert.Equal(t, []string{"read"}, c.Scopes())
	assert.Equal(t, []string{"client_secret_basic"}, c.AuthMethods())

	assert.True(t, c.SecretMatches("s3cr3t"))
	assert.False(t, c.SecretMatches("wrong"))
	assert.False(t, c.SecretMatches(""))
}

func TestStaticIssuer(t *testing.T) {
	t.Parallel()

	resolver := oauth2.StaticIssuer("https://auth.example", "api")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)

	iss, aud, err := resolver.Resolve(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "https://auth.example", iss)
	assert.Equal(t, "api", aud)
}
