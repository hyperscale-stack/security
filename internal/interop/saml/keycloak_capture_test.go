// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlinterop_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	samlsp "github.com/hyperscale-stack/security/saml/sp"
	"github.com/hyperscale-stack/security/saml/sp/storage/memory"
	"github.com/stretchr/testify/require"
)

// The pinned Keycloak fixture: a real response signed by Keycloak
// (Apache Santuario), replayed offline at its capture time.
const (
	keycloakDir       = "testdata/keycloak-26.0.7"
	keycloakRealm     = "samlsp"
	keycloakConnID    = "kc"
	keycloakSPEntity  = "https://sp.example.test/saml/kc"
	keycloakACSURL    = "https://sp.example.test/saml/kc/acs"
	keycloakUser      = "alice"
	keycloakUserEmail = "alice@example.com"
)

// keycloakLogin is what the capture recorded: the transaction BeginLogin
// stored, the browser's binding cookie, and Keycloak's HTTP-POST form.
type keycloakLogin struct {
	CapturedAt   time.Time                `json:"captured_at"`
	Transaction  samlsp.TransactionRecord `json:"transaction"`
	Cookie       string                   `json:"cookie"`
	RelayState   string                   `json:"relay_state"`
	SAMLResponse string                   `json:"saml_response"`
}

// recordingStore records the transaction BeginLogin saves.
type recordingStore struct {
	*memory.Store

	saved samlsp.TransactionRecord
}

func (r *recordingStore) SaveTransaction(ctx context.Context, rec *samlsp.TransactionRecord) error {
	r.saved = *rec

	return r.Store.SaveTransaction(ctx, rec)
}

// regenerateKeycloakFixture asks TestCaptureKeycloakFixture to rewrite the
// pinned fixture: the environment of the opt-in Keycloak suite alone never
// does.
var regenerateKeycloakFixture = flag.Bool("keycloak.fixture", false,
	"regenerate "+keycloakDir+" from a disposable Keycloak 26.0.7 (TestCaptureKeycloakFixture)")

// TestCaptureKeycloakFixture regenerates the pinned fixture from a
// disposable Keycloak 26.0.7: it deletes and recreates the realm "samlsp",
// with a user and a SAML client, so never point it at a shared instance.
// The admin credentials come from the environment; none is committed:
//
//	export SAMLSP_KEYCLOAK_ADMIN_PASSWORD="$(openssl rand -hex 16)"
//	docker run --rm -p 127.0.0.1:18080:8080 \
//	  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
//	  -e KC_BOOTSTRAP_ADMIN_PASSWORD="$SAMLSP_KEYCLOAK_ADMIN_PASSWORD" \
//	  quay.io/keycloak/keycloak:26.0.7 start-dev
//	SAMLSP_KEYCLOAK_URL=http://127.0.0.1:18080 go test -run TestCaptureKeycloakFixture . -args -keycloak.fixture
//
// SAMLSP_KEYCLOAK_ADMIN_USER defaults to "admin". The test is skipped
// unless -keycloak.fixture, SAMLSP_KEYCLOAK_URL and
// SAMLSP_KEYCLOAK_ADMIN_PASSWORD are all given, and it refuses any other
// Keycloak version than the fixture's.
func TestCaptureKeycloakFixture(t *testing.T) {
	base, password := os.Getenv("SAMLSP_KEYCLOAK_URL"), os.Getenv("SAMLSP_KEYCLOAK_ADMIN_PASSWORD")
	if !*regenerateKeycloakFixture || base == "" || password == "" {
		t.Skip("regenerate " + keycloakDir + " with -args -keycloak.fixture, SAMLSP_KEYCLOAK_URL and " +
			"SAMLSP_KEYCLOAK_ADMIN_PASSWORD (a disposable Keycloak 26.0.7)")
	}

	user := os.Getenv("SAMLSP_KEYCLOAK_ADMIN_USER")
	if user == "" {
		user = "admin"
	}

	// Keycloak's realm metadata sets WantAuthnRequestsSigned: the SP signs
	// with a throwaway key registered on the client.
	spKey := newKey(t, "sp")

	kc := keycloakAdmin{t: t, base: base, token: keycloakToken(t, base, user, password)}
	require.Equal(t, "26.0.7", kc.serverVersion(), "the fixture is Keycloak 26.0.7's")
	kc.deleteRealm()
	kc.post("/admin/realms", map[string]any{"realm": keycloakRealm, "enabled": true})
	kc.post("/admin/realms/"+keycloakRealm+"/users", map[string]any{
		"username": keycloakUser, "enabled": true, "email": keycloakUserEmail, "emailVerified": true,
		"firstName": "Alice", "lastName": "Example",
		"credentials": []map[string]any{{"type": "password", "value": "alice-password", "temporary": false}},
	})
	kc.post("/admin/realms/"+keycloakRealm+"/clients", map[string]any{
		"clientId": keycloakSPEntity, "protocol": "saml", "enabled": true,
		"redirectUris": []string{keycloakACSURL}, "frontchannelLogout": false,
		"attributes": map[string]string{
			"saml_assertion_consumer_url_post": keycloakACSURL,
			"saml.server.signature":            "true",
			"saml.assertion.signature":         "true",
			"saml.signature.algorithm":         "RSA_SHA256",
			"saml.client.signature":            "true",
			"saml.signing.certificate":         base64.StdEncoding.EncodeToString(spKey.cert.Raw),
			"saml.encrypt":                     "false",
			"saml.authnstatement":              "true",
			"saml_force_name_id_format":        "true",
			"saml_name_id_format":              "persistent",
		},
	})

	metadata := httpGet(t, http.DefaultClient, base+"/realms/"+keycloakRealm+"/protocol/saml/descriptor")

	store := &recordingStore{Store: memory.New()}
	sp := keycloakSP(t, metadata, store, time.Now, &spKey)

	rec := httptest.NewRecorder()
	target, err := sp.BeginLogin(context.Background(), rec, httptest.NewRequest(http.MethodGet, keycloakSPEntity, nil),
		keycloakConnID, samlsp.LoginOptions{AppState: "/after-login"})
	require.NoError(t, err)

	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	browser := &http.Client{Jar: jar}
	page := httpGet(t, browser, target)

	action := regexp.MustCompile(`<form[^>]+id="kc-form-login"[^>]+action="([^"]+)"`).FindSubmatch(page)
	require.NotNil(t, action, "Keycloak login form: %.300s", page)

	resp, err := browser.PostForm(html.UnescapeString(string(action[1])),
		url.Values{"username": {keycloakUser}, "password": {"alice-password"}, "credentialId": {""}})
	require.NoError(t, err)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	field := func(name string) string {
		m := regexp.MustCompile(`(?i)name="` + name + `"\s+value="([^"]*)"`).FindSubmatch(body)
		require.NotNil(t, m, "%s in Keycloak's POST form: %.300s", name, body)

		return html.UnescapeString(string(m[1]))
	}

	login := keycloakLogin{
		CapturedAt:   time.Now().UTC().Truncate(time.Second),
		Transaction:  store.saved,
		Cookie:       cookies[0].Value,
		RelayState:   field("RelayState"),
		SAMLResponse: field("SAMLResponse"),
	}

	out, err := json.MarshalIndent(login, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(keycloakDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(keycloakDir, "idp-metadata.xml"), metadata, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(keycloakDir, "login.json"), append(out, '\n'), 0o600))
}

// keycloakSP is the Service Provider of the fixture, at a given clock.
func keycloakSP(t *testing.T, metadata []byte, store samlsp.Storage, now func() time.Time, key *testKey) *samlsp.ServiceProvider {
	t.Helper()

	idp, err := samlsp.ParseIdentityProviderMetadata(metadata, samlsp.MetadataOptions{Now: now})
	require.NoError(t, err)

	conn := samlsp.Connection{
		ID: keycloakConnID, SPEntityID: keycloakSPEntity, ACSURL: keycloakACSURL,
		IdentityProvider: *idp, NameIDFormat: samlsp.NameIDFormatPersistent,
	}

	cfg := samlsp.Config{
		Connections: samlsp.ConnectionResolverFunc(func(_ context.Context, id string) (*samlsp.Connection, error) {
			if id != conn.ID {
				return nil, samlsp.ErrUnknownConnection
			}

			c := conn

			return &c, nil
		}),
		Transactions: store,
		ReplayCache:  store,
		Now:          now,
	}

	if key != nil {
		cfg.SigningKey, cfg.SigningCertificate = key.signer, key.cert
	}

	sp, err := samlsp.New(cfg)
	require.NoError(t, err)

	return sp
}

// keycloakAdmin calls the Keycloak admin REST API.
type keycloakAdmin struct {
	t           *testing.T
	base, token string
}

func keycloakToken(t *testing.T, base, user, password string) string {
	t.Helper()

	resp, err := http.PostForm(base+"/realms/master/protocol/openid-connect/token", url.Values{
		"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {user}, "password": {password},
	})
	require.NoError(t, err)

	defer resp.Body.Close()

	var tok struct {
		AccessToken string `json:"access_token"`
	}

	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tok))
	require.NotEmpty(t, tok.AccessToken)

	return tok.AccessToken
}

// deleteRealm removes the fixture realm left by a previous capture.
// serverVersion returns the version of the Keycloak server.
func (k keycloakAdmin) serverVersion() string {
	k.t.Helper()

	req, err := http.NewRequest(http.MethodGet, k.base+"/admin/serverinfo", nil)
	require.NoError(k.t, err)
	req.Header.Set("Authorization", "Bearer "+k.token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(k.t, err)

	defer resp.Body.Close()

	require.Equal(k.t, http.StatusOK, resp.StatusCode)

	var info struct {
		SystemInfo struct {
			Version string `json:"version"`
		} `json:"systemInfo"`
	}

	require.NoError(k.t, json.NewDecoder(resp.Body).Decode(&info))

	return info.SystemInfo.Version
}

func (k keycloakAdmin) deleteRealm() {
	k.t.Helper()

	req, err := http.NewRequest(http.MethodDelete, k.base+"/admin/realms/"+keycloakRealm, nil)
	require.NoError(k.t, err)

	req.Header.Set("Authorization", "Bearer "+k.token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(k.t, err)
	require.NoError(k.t, resp.Body.Close())
	require.Contains(k.t, []int{http.StatusNoContent, http.StatusNotFound}, resp.StatusCode)
}

func (k keycloakAdmin) post(path string, body any) {
	k.t.Helper()

	raw, err := json.Marshal(body)
	require.NoError(k.t, err)

	req, err := http.NewRequest(http.MethodPost, k.base+path, bytes.NewReader(raw))
	require.NoError(k.t, err)

	req.Header.Set("Authorization", "Bearer "+k.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(k.t, err)

	defer resp.Body.Close()

	msg, _ := io.ReadAll(resp.Body)
	require.Equal(k.t, http.StatusCreated, resp.StatusCode, fmt.Sprintf("POST %s: %s", path, msg))
}

func httpGet(t *testing.T, client *http.Client, u string) []byte {
	t.Helper()

	resp, err := client.Get(u)
	require.NoError(t, err)

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "GET %s: %.300s", u, body)

	return body
}
