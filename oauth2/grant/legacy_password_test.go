// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grant_test

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeROVerifier is a test ResourceOwnerVerifier.
type fakeROVerifier struct {
	subject string
	err     error
}

func (v fakeROVerifier) VerifyResourceOwner(_ context.Context, _, _ string) (string, error) {
	return v.subject, v.err
}

func passwordForm(username, password, scope string) url.Values {
	form := url.Values{}

	if username != "" {
		form.Set("username", username)
	}

	if password != "" {
		form.Set("password", password)
	}

	if scope != "" {
		form.Set("scope", scope)
	}

	return form
}

func TestNewLegacyPasswordPanics(t *testing.T) {
	t.Parallel()

	good := fakeROVerifier{subject: subject}
	full := grant.Config{Storage: newStore(), AccessTokens: newAccessGen(), AccessTTL: time.Hour}

	assert.Panics(t, func() { grant.NewLegacyPassword(grant.Config{}, good) })
	assert.Panics(t, func() { grant.NewLegacyPassword(full, nil) })
}

func TestLegacyPasswordType(t *testing.T) {
	t.Parallel()

	g := grant.NewLegacyPassword(
		grant.Config{Storage: newStore(), AccessTokens: newAccessGen(), AccessTTL: time.Hour},
		fakeROVerifier{subject: subject},
	)
	assert.Equal(t, "password", g.Type())
}

func TestLegacyPasswordHappyPath(t *testing.T) {
	t.Parallel()

	g := grant.NewLegacyPassword(grant.Config{
		Storage: newStore(), AccessTokens: newAccessGen(),
		RefreshTokens: newRefreshGen(), AccessTTL: time.Hour, RefreshTTL: 24 * time.Hour,
	}, fakeROVerifier{subject: "alice"})

	resp, err := g.Handle(context.Background(), grant.Request{
		Client: newClient(), Form: passwordForm("alice", "s3cr3t", "read:mail"),
		Issuer: "https://auth.example", Audience: "api", Now: time.Now(),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Pair.Access.Token)
	assert.Equal(t, "alice", resp.Pair.Access.Subject)
	assert.Equal(t, "read:mail", resp.Scope)
	assert.NotNil(t, resp.Pair.Refresh, "a refresh token is issued when configured")
}

func TestLegacyPasswordWithoutRefreshGenerator(t *testing.T) {
	t.Parallel()

	g := grant.NewLegacyPassword(
		grant.Config{Storage: newStore(), AccessTokens: newAccessGen(), AccessTTL: time.Hour},
		fakeROVerifier{subject: "alice"},
	)

	resp, err := g.Handle(context.Background(), grant.Request{
		Client: newClient(), Form: passwordForm("alice", "s3cr3t", ""), Now: time.Now(),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Pair.Access.Token)
	assert.Nil(t, resp.Pair.Refresh)
}

func TestLegacyPasswordMissingCredentials(t *testing.T) {
	t.Parallel()

	g := grant.NewLegacyPassword(
		grant.Config{Storage: newStore(), AccessTokens: newAccessGen(), AccessTTL: time.Hour},
		fakeROVerifier{subject: "alice"},
	)

	for _, form := range []url.Values{
		passwordForm("", "s3cr3t", ""),
		passwordForm("alice", "", ""),
		passwordForm("", "", ""),
	} {
		_, err := g.Handle(context.Background(), grant.Request{
			Client: newClient(), Form: form, Now: time.Now(),
		})
		require.Error(t, err)
		assert.Equal(t, oauth2.CodeInvalidRequest, oauth2.IsCode(err))
	}
}

func TestLegacyPasswordInvalidCredentials(t *testing.T) {
	t.Parallel()

	g := grant.NewLegacyPassword(
		grant.Config{Storage: newStore(), AccessTokens: newAccessGen(), AccessTTL: time.Hour},
		fakeROVerifier{err: errors.New("no such user")},
	)

	_, err := g.Handle(context.Background(), grant.Request{
		Client: newClient(), Form: passwordForm("ghost", "whatever", ""), Now: time.Now(),
	})
	require.Error(t, err)
	assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))
}

func TestLegacyPasswordGrantTypeNotAllowed(t *testing.T) {
	t.Parallel()

	g := grant.NewLegacyPassword(
		grant.Config{Storage: newStore(), AccessTokens: newAccessGen(), AccessTTL: time.Hour},
		fakeROVerifier{subject: "alice"},
	)

	client := &oauth2.DefaultClient{
		IDValue:         clientID,
		TypeValue:       oauth2.ClientConfidential,
		GrantTypeValues: []string{"authorization_code"}, // not "password"
	}

	_, err := g.Handle(context.Background(), grant.Request{
		Client: client, Form: passwordForm("alice", "s3cr3t", ""), Now: time.Now(),
	})
	require.Error(t, err)
	assert.Equal(t, oauth2.CodeUnauthorizedClient, oauth2.IsCode(err))
}

func TestLegacyPasswordRejectsBroadenedScope(t *testing.T) {
	t.Parallel()

	g := grant.NewLegacyPassword(
		grant.Config{Storage: newStore(), AccessTokens: newAccessGen(), AccessTTL: time.Hour},
		fakeROVerifier{subject: "alice"},
	)

	_, err := g.Handle(context.Background(), grant.Request{
		Client: newClient(), Form: passwordForm("alice", "s3cr3t", "billing:write"), Now: time.Now(),
	})
	require.Error(t, err)
	assert.Equal(t, oauth2.CodeInvalidScope, oauth2.IsCode(err))
}
