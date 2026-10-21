// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlinterop_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	samlsp "github.com/hyperscale-stack/security/saml/sp"
	"github.com/hyperscale-stack/security/saml/sp/storage/memory"
	"github.com/stretchr/testify/require"
)

// loadKeycloakCases reads the pinned Keycloak responses (TestKeycloakLive
// -keycloak.capture).
func loadKeycloakCases(t *testing.T) []keycloakCase {
	t.Helper()

	files, err := filepath.Glob(filepath.Join(keycloakDir26, "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, files, "no pinned Keycloak %s responses", keycloakVersion)

	cases := make([]keycloakCase, 0, len(files))

	for _, f := range files {
		raw, err := os.ReadFile(f)
		require.NoError(t, err)

		var c keycloakCase
		require.NoError(t, json.Unmarshal(raw, &c), f)

		cases = append(cases, c)
	}

	return cases
}

// replayKeycloak completes a pinned case three minutes after its capture
// (goxmldsig checks the realm certificate at now - ClockSkew), optionally
// with the SHA-1 opt-in, and with an optional replacement response.
func replayKeycloak(t *testing.T, c keycloakCase, allowSHA1 bool, response string) (*samlsp.LoginResult, error) {
	t.Helper()

	at := c.CapturedAt.Add(3 * time.Minute)
	now := func() time.Time { return at }

	idp, err := samlsp.ParseIdentityProviderMetadata([]byte(c.Metadata), samlsp.MetadataOptions{Now: now})
	require.NoError(t, err)

	conn := samlsp.Connection{
		ID: c.Connection.ID, SPEntityID: c.Connection.SPEntityID, ACSURL: c.Connection.ACSURL,
		IdentityProvider: *idp, InsecureAllowSHA1: allowSHA1,
	}

	store := memory.New(memory.WithClock(now))
	rec := withIntegrity(c.Transaction)
	require.NoError(t, store.SaveTransaction(context.Background(), &rec))

	sp, err := samlsp.New(samlsp.Config{
		Connections: samlsp.ConnectionResolverFunc(func(_ context.Context, id string) (*samlsp.Connection, error) {
			if id != conn.ID {
				return nil, samlsp.ErrUnknownConnection
			}

			cp := conn

			return &cp, nil
		}),
		Transactions: store, ReplayCache: store, TransactionKeys: testTransactionKeys, Now: now,
	})
	require.NoError(t, err)

	if response == "" {
		response = c.Response
	}

	form := url.Values{"SAMLResponse": {response}, "RelayState": {c.RelayState}}
	req := httptest.NewRequest(http.MethodPost, c.Connection.ACSURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: samlsp.DefaultCookieName, Value: c.Cookie})

	return sp.CompleteLogin(context.Background(), req, conn.ID)
}

// requireOutcome checks a completion against a declared outcome: the
// identity, the status, or the full refusal message (sentinel and static
// detail, no IdP-controlled text).
func requireOutcome(t *testing.T, e keycloakExpect, about string, res *samlsp.LoginResult, err error) {
	t.Helper()

	switch e.Error {
	case "":
		require.NoError(t, err, about)
		require.Equal(t, e.NameIDFormat, res.Identity.NameID.Format)

		if e.NameIDValue != "" {
			require.Equal(t, e.NameIDValue, res.Identity.NameID.Value)
		}
	case "ErrResponseStatus":
		var se *samlsp.StatusError
		require.ErrorAs(t, err, &se, about)
		require.Equal(t, e.StatusCode, se.Code)
		require.Equal(t, e.StatusSubCode, se.SubCode)
	default:
		sentinel := keycloakSentinel(t, e.Error)
		require.ErrorIs(t, err, sentinel, about)
		require.ErrorIs(t, err, samlsp.ErrRejected)

		want := sentinel.Error()
		if e.Detail != "" {
			want += " (" + e.Detail + ")"
		}

		require.Equal(t, want, err.Error())
	}
}

// TestKeycloakMatrix replays every pinned Keycloak response offline: real
// Apache Santuario signatures in every placement, algorithm and NameID
// format Keycloak offers, its error statuses and an IdP key rollover.
func TestKeycloakMatrix(t *testing.T) {
	t.Parallel()

	for _, c := range loadKeycloakCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			t.Parallel()

			res, err := replayKeycloak(t, c, false, "")
			requireOutcome(t, c.Expect, c.About, res, err)

			if c.Expect.WithSHA1OptIn == "accepted" {
				_, err := replayKeycloak(t, c, true, "")
				require.NoError(t, err, "accepted with InsecureAllowSHA1")
			}
		})
	}
}

// TestTestdataHoldsNoSecret checks that the pinned captures hold no private
// key and record only the allowlisted, non-secret client settings.
func TestTestdataHoldsNoSecret(t *testing.T) {
	t.Parallel()

	err := filepath.WalkDir("testdata", func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}

		data, err := os.ReadFile(path)
		require.NoError(t, err)

		lower := strings.ToLower(string(data))

		for _, marker := range []string{"private key", "private.key", "password", "secret"} {
			require.False(t, strings.Contains(lower, marker), "%s contains %q", path, marker)
		}

		return nil
	})
	require.NoError(t, err)

	allowed := make(map[string]bool, len(allowedClientSettings))
	for _, name := range allowedClientSettings {
		allowed[name] = true
	}

	for _, c := range loadKeycloakCases(t) {
		for name := range c.Client {
			require.True(t, allowed[name], "%s records the client setting %s", c.Name, name)
		}
	}
}
