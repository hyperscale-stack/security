// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlinterop_test

import (
	"context"
	"encoding/base64"
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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestKeycloakResponse replays a login pinned from Keycloak 26.0.7 (see
// TestCaptureKeycloakFixture): its Response and Assertion signatures come
// from Apache Santuario, not from goxmldsig, the verifier; the assertion
// uses a default namespace declaration, KeyInfo carries a KeyName, and the
// roles arrive as repeated Attribute elements.
func TestKeycloakResponse(t *testing.T) {
	t.Parallel()

	metadata, err := os.ReadFile(filepath.Join(keycloakDir, "idp-metadata.xml"))
	require.NoError(t, err)

	raw, err := os.ReadFile(filepath.Join(keycloakDir, "login.json"))
	require.NoError(t, err)

	var login keycloakLogin
	require.NoError(t, json.Unmarshal(raw, &login))

	// Replay three minutes after the capture: goxmldsig checks the
	// certificate at now - ClockSkew and Keycloak minted it right before.
	at := login.CapturedAt.Add(3 * time.Minute)

	complete := func(samlResponse string, now time.Time) (*samlsp.LoginResult, error) {
		store := memory.New()
		rec := login.Transaction
		require.NoError(t, store.SaveTransaction(context.Background(), &rec))

		sp := keycloakSP(t, metadata, store, func() time.Time { return now }, nil)

		form := url.Values{"SAMLResponse": {samlResponse}, "RelayState": {login.RelayState}}
		req := httptest.NewRequest(http.MethodPost, keycloakACSURL, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: samlsp.DefaultCookieName, Value: login.Cookie})

		return sp.CompleteLogin(context.Background(), req, keycloakConnID)
	}

	res, err := complete(login.SAMLResponse, at)
	require.NoError(t, err)

	id := res.Identity
	assert.Equal(t, "http://127.0.0.1:18080/realms/"+keycloakRealm, id.Issuer)
	assert.Equal(t, keycloakSPEntity, id.Audience)
	assert.Equal(t, samlsp.NameIDFormatPersistent, id.NameID.Format)
	assert.Regexp(t, `^G-[0-9a-f-]{36}$`, id.NameID.Value)
	assert.Contains(t, id.AttributeValues("Role"), "default-roles-"+keycloakRealm)
	assert.NotEmpty(t, id.SessionIndex)
	assert.False(t, id.SessionNotOnOrAfter.IsZero())
	assert.Equal(t, "/after-login", res.AppState)

	// The signatures cover what matters, and the assertion expires.
	xml, err := base64.StdEncoding.DecodeString(login.SAMLResponse)
	require.NoError(t, err)

	tampered := strings.Replace(string(xml), "default-roles-"+keycloakRealm, "admin", 1)
	_, err = complete(base64.StdEncoding.EncodeToString([]byte(tampered)), at)
	require.ErrorIs(t, err, samlsp.ErrInvalidSignature)

	_, err = complete(login.SAMLResponse, login.CapturedAt.Add(8*time.Minute))
	require.ErrorIs(t, err, samlsp.ErrAssertionExpired)
}
