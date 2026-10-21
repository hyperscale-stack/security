// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient_test

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hyperscale-stack/security"
	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	"github.com/hyperscale-stack/security/outbound"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func userinfoBody(contentType, body string, status int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

// loggedIn runs a login and returns the client and its identity.
func loggedIn(t *testing.T, op *fakeOP) (*oidcclient.Client, *oidcclient.Identity) {
	t.Helper()

	c := op.client(t)
	id, err := op.login(t, c)
	require.NoError(t, err)

	return c, id
}

// TestUserInfo checks OpenID Connect Core §5.3: a GET with the access token
// as a Bearer token (RFC 6750 §2.1), a JSON response whose sub is exactly
// the identity's.
func TestUserInfo(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)

	var seen *http.Request

	op.set(func(op *fakeOP) {
		op.userinfo = func(w http.ResponseWriter, r *http.Request) {
			seen = r.Clone(context.Background())
			writeJSON(w, http.StatusOK, map[string]any{"sub": testSubject, "email": "jane@example.com", "groups": []string{"a"}})
		}
	})

	c, id := loggedIn(t, op)

	info, err := c.UserInfo(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, testSubject, info.Subject)

	var claims struct {
		Email  string   `json:"email"`
		Groups []string `json:"groups"`
	}

	require.NoError(t, info.Decode(&claims))
	assert.Equal(t, "jane@example.com", claims.Email)
	assert.Equal(t, []string{"a"}, claims.Groups)

	require.NotNil(t, seen)
	assert.Equal(t, http.MethodGet, seen.Method)
	assert.Equal(t, "Bearer "+testAccessToken, seen.Header.Get("Authorization"))
	assert.Equal(t, "application/json", seen.Header.Get("Accept"))
	assert.Empty(t, seen.URL.RawQuery, "the token travels in the header only")

	var wrong struct {
		Email int `json:"email"`
	}
	require.Error(t, info.Decode(&wrong))

	var buf bytes.Buffer

	slog.New(slog.NewJSONHandler(&buf, nil)).Info("userinfo", "v", *info)
	assert.NotContains(t, buf.String(), "jane@example.com", "slog prints the subject, not the claims")
	assert.Contains(t, buf.String(), testSubject)
}

func TestUserInfoResponses(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		handler http.HandlerFunc
		err     error
	}{
		"other subject":    {userinfoBody("application/json", `{"sub":"other"}`, 200), oidcclient.ErrUserInfoSubject},
		"missing subject":  {userinfoBody("application/json", `{"email":"jane@example.com"}`, 200), oidcclient.ErrUserInfoSubject},
		"duplicate sub":    {userinfoBody("application/json", `{"sub":"`+testSubject+`","sub":"other"}`, 200), oidcclient.ErrUserInfo},
		"case-variant sub": {userinfoBody("application/json", `{"sub":"`+testSubject+`","SUB":"other"}`, 200), oidcclient.ErrUserInfo},
		"sub not a string": {userinfoBody("application/json", `{"sub":248289761001}`, 200), oidcclient.ErrUserInfo},
		"not an object":    {userinfoBody("application/json", `["`+testSubject+`"]`, 200), oidcclient.ErrUserInfo},
		"signed response":  {userinfoBody("application/jwt", `eyJ.x.y`, 200), oidcclient.ErrUserInfoUnsupported},
		"html":             {userinfoBody("text/html", `<html>`, 200), oidcclient.ErrUserInfo},
		"JSON as text":     {userinfoBody("text/plain", `{"sub":"`+testSubject+`"}`, 200), oidcclient.ErrUserInfo},
		"401 with claims":  {userinfoBody("application/json", `{"sub":"`+testSubject+`"}`, 401), oidcclient.ErrUserInfo},
		"203 with claims":  {userinfoBody("application/json", `{"sub":"`+testSubject+`"}`, 203), oidcclient.ErrUserInfo},
		"unauthorized": {func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			w.WriteHeader(http.StatusUnauthorized)
		}, oidcclient.ErrUserInfo},
		"server error": {userinfoBody("application/json", `{}`, 500), oidcclient.ErrUserInfo},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t)
			op.set(func(op *fakeOP) { op.userinfo = tc.handler })
			c, id := loggedIn(t, op)

			info, err := c.UserInfo(context.Background(), id)
			require.ErrorIs(t, err, tc.err)
			assert.Nil(t, info, "UserInfo values of a failed check are never returned (Core §5.3.2)")

			if tc.err == oidcclient.ErrUserInfoSubject {
				require.ErrorIs(t, err, security.ErrInvalidCredentials)
			}
		})
	}
}

// TestUserInfoSubjectIsCaseSensitive checks the exact comparison of Core
// §5.3.2 (and §14: code point by code point).
func TestUserInfoSubjectIsCaseSensitive(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	op.set(func(op *fakeOP) {
		op.claimsHook = func(_ *grant, claims map[string]any) { claims["sub"] = "Jane.Doe" }
		op.userinfo = userinfoBody("application/json", `{"sub":"jane.doe"}`, 200)
	})
	c, id := loggedIn(t, op)

	_, err := c.UserInfo(context.Background(), id)
	require.ErrorIs(t, err, oidcclient.ErrUserInfoSubject)
}

// TestUserInfoRefusesForeignIdentity checks that the access token of a
// login is only ever sent to the UserInfo endpoint of its own connection.
func TestUserInfoRefusesForeignIdentity(t *testing.T) {
	t.Parallel()

	cases := map[string]func(*oidcclient.Identity){
		"other connection": func(id *oidcclient.Identity) { id.ConnectionID = "other" },
		"other issuer":     func(id *oidcclient.Identity) { id.Issuer = "https://other.example.com" },
		"no subject":       func(id *oidcclient.Identity) { id.Subject = "" },
		"no access token":  func(id *oidcclient.Identity) { id.Tokens.AccessToken = oidcclient.Secret{} },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t)
			op.set(func(op *fakeOP) { op.userinfo = userinfoBody("application/json", `{"sub":"`+testSubject+`"}`, 200) })
			c, id := loggedIn(t, op)

			foreign := *id
			mutate(&foreign)

			_, err := c.UserInfo(context.Background(), &foreign)
			require.ErrorIs(t, err, oidcclient.ErrUserInfo)
			assert.Zero(t, op.hitCount("/userinfo"))
		})
	}

	t.Run("nil identity", func(t *testing.T) {
		t.Parallel()

		op := newFakeOP(t)
		_, err := op.client(t).UserInfo(context.Background(), nil)
		require.ErrorIs(t, err, oidcclient.ErrUserInfo)
	})

	t.Run("no endpoint", func(t *testing.T) {
		t.Parallel()

		op := newFakeOP(t)
		op.set(func(op *fakeOP) { delete(op.metadata, "userinfo_endpoint") })
		c, id := loggedIn(t, op)

		_, err := c.UserInfo(context.Background(), id)
		require.ErrorIs(t, err, oidcclient.ErrUserInfo)
		assert.ErrorContains(t, err, "no UserInfo endpoint", "refused before any request is built")
	})
}

func TestUserInfoTransport(t *testing.T) {
	t.Parallel()

	t.Run("redirect not followed", func(t *testing.T) {
		t.Parallel()

		var hits atomic.Int64

		elsewhere := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
		t.Cleanup(elsewhere.Close)

		op := newFakeOP(t)
		op.set(func(op *fakeOP) {
			op.userinfo = func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, elsewhere.URL+"/userinfo", http.StatusFound)
			}
		})
		c := op.client(t, func(cfg *oidcclient.Config) { cfg.Outbound.MaxRedirects = 5 })
		id, err := op.login(t, c)
		require.NoError(t, err)

		_, err = c.UserInfo(context.Background(), id)
		require.ErrorIs(t, err, oidcclient.ErrUserInfo)
		assert.Zero(t, hits.Load(), "the access token never follows a redirect")
	})

	t.Run("redirect on the same origin not followed", func(t *testing.T) {
		t.Parallel()

		op := newFakeOP(t)
		c := op.client(t, maxRedirects(5))
		id, err := op.login(t, c)
		require.NoError(t, err)

		op.set(func(op *fakeOP) { op.redirects = map[string]string{"/userinfo": "/userinfo-v2"} })

		_, err = c.UserInfo(context.Background(), id)
		require.ErrorIs(t, err, oidcclient.ErrUserInfo)
		require.ErrorIs(t, err, outbound.ErrRedirectNotAllowed)
		assert.Zero(t, op.hitCount("/userinfo-v2"), "the access token never follows a redirect, even on the same origin")
	})

	t.Run("oversized", func(t *testing.T) {
		t.Parallel()

		op := newFakeOP(t)
		op.set(func(op *fakeOP) {
			op.userinfo = userinfoBody("application/json", `{"sub":"`+testSubject+`","pad":"`+strings.Repeat("p", 8192)+`"}`, 200)
		})
		c := op.client(t, func(cfg *oidcclient.Config) { cfg.Outbound.MaxResponseBytes = 4096 })
		id, err := op.login(t, c)
		require.NoError(t, err)

		_, err = c.UserInfo(context.Background(), id)
		require.ErrorIs(t, err, oidcclient.ErrUserInfo)
	})
}
