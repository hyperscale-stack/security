// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlinterop_test

// Live interoperability with Keycloak (Apache Santuario signer), opt-in:
//
//	docker compose -f compose.yaml up -d --wait keycloak
//	SAMLSP_KEYCLOAK_URL=http://127.0.0.1:18080 SAMLSP_KEYCLOAK_ADMIN_PASSWORD=… \
//	  go test -run '^TestKeycloakLive$' -count=1 . [-args -keycloak.capture]
//
// Each run creates a realm with a random name and a user with a random
// password, and deletes the realm at the end. With -keycloak.capture the
// responses are written to testdata/keycloak-<version>/ and replayed
// offline in CI by TestKeycloakMatrix and TestKeycloakWrapping. Only signed
// messages, public certificates and allowlisted, non-secret client settings
// are recorded.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	samlsp "github.com/hyperscale-stack/security/saml/sp"
	"github.com/hyperscale-stack/security/saml/sp/storage/memory"
	"github.com/stretchr/testify/require"
)

var captureKeycloak = flag.Bool("keycloak.capture", false, "write the Keycloak responses to testdata (TestKeycloakLive)")

// keycloakVersion is the pinned image of compose.yaml.
const keycloakVersion = "26.7.4"

// keycloakCase is one pinned Keycloak response and what it must yield.
type keycloakCase struct {
	Name        string                   `json:"name"`
	About       string                   `json:"about"`
	CapturedAt  time.Time                `json:"captured_at"`
	Metadata    string                   `json:"metadata"` // realm descriptor at verification time
	Connection  keycloakConnection       `json:"connection"`
	Client      map[string]string        `json:"client_settings"` // allowlisted
	Transaction samlsp.TransactionRecord `json:"transaction"`
	Cookie      string                   `json:"cookie"`
	RelayState  string                   `json:"relay_state"`
	Response    string                   `json:"saml_response"`
	Expect      keycloakExpect           `json:"expect"`
}

// keycloakConnection is the SP side of a case.
type keycloakConnection struct {
	ID         string `json:"id"`
	SPEntityID string `json:"sp_entity_id"`
	ACSURL     string `json:"acs_url"`
}

// keycloakExpect is the declared outcome, with and without the SHA-1
// opt-in where it matters.
type keycloakExpect struct {
	Error         string `json:"error,omitempty"` // sentinel name; "" = accepted
	Detail        string `json:"detail,omitempty"`
	NameIDFormat  string `json:"nameid_format,omitempty"`
	NameIDValue   string `json:"nameid_value,omitempty"`
	StatusCode    string `json:"status_code,omitempty"`
	StatusSubCode string `json:"status_sub_code,omitempty"`
	WithSHA1OptIn string `json:"with_sha1_opt_in,omitempty"` // "accepted" when the opt-in accepts it
}

// allowedClientSettings are the client attributes recorded with a case:
// never keys or certificates (plan review F12).
var allowedClientSettings = []string{
	"saml.server.signature", "saml.assertion.signature", "saml.signature.algorithm", "saml.client.signature",
	"saml.encrypt", "saml_name_id_format", "saml_force_name_id_format", "saml.server.signature.keyinfo.ext",
}

// kcAdmin drives the Keycloak admin API of one disposable realm.
type kcAdmin struct {
	t      *testing.T
	base   string
	token  string
	realm  string
	client *http.Client
}

func newKCAdmin(t *testing.T, base string) *kcAdmin {
	t.Helper()

	user := os.Getenv("SAMLSP_KEYCLOAK_ADMIN_USER")
	if user == "" {
		user = "admin"
	}

	pw := os.Getenv("SAMLSP_KEYCLOAK_ADMIN_PASSWORD")
	require.NotEmpty(t, pw, "SAMLSP_KEYCLOAK_ADMIN_PASSWORD (never committed)")

	k := &kcAdmin{t: t, base: base, client: &http.Client{Timeout: 30 * time.Second}}

	resp, err := k.client.PostForm(base+"/realms/master/protocol/openid-connect/token", url.Values{
		"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {user}, "password": {pw},
	})
	require.NoError(t, err)

	defer resp.Body.Close()

	var tok struct {
		AccessToken string `json:"access_token"`
	}

	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tok))
	require.NotEmpty(t, tok.AccessToken)

	k.token = tok.AccessToken

	return k
}

// do calls the admin API and returns the body, requiring one of want.
func (k *kcAdmin) do(method, path string, body any, want ...int) []byte {
	k.t.Helper()

	var rd io.Reader

	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		require.NoError(k.t, err)

		rd = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(context.Background(), method, k.base+path, rd)
	require.NoError(k.t, err)

	req.Header.Set("Authorization", "Bearer "+k.token)

	if _, isXML := body.([]byte); isXML {
		req.Header.Set("Content-Type", "application/xml")
	} else if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := k.client.Do(req)
	require.NoError(k.t, err)

	defer resp.Body.Close()

	out, err := io.ReadAll(resp.Body)
	require.NoError(k.t, err)
	require.Contains(k.t, want, resp.StatusCode, "%s %s: %.300s", method, path, out)

	return out
}

// randomSecret returns a fresh random value (never a committed secret).
func randomSecret() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)

	return hex.EncodeToString(b)
}

// setUp creates the realm and the user; the realm is deleted at the end.
func (k *kcAdmin) setUp(user, email string) (password string) {
	k.t.Helper()

	k.realm = "samlsp-" + randomSecret()[:12]
	k.do(http.MethodPost, "/admin/realms", map[string]any{"realm": k.realm, "enabled": true}, http.StatusCreated)
	k.t.Cleanup(func() { k.do(http.MethodDelete, "/admin/realms/"+k.realm, nil, http.StatusNoContent) })

	password = randomSecret()
	k.do(http.MethodPost, "/admin/realms/"+k.realm+"/users", map[string]any{
		"username": user, "enabled": true, "email": email, "emailVerified": true, "firstName": "Alice", "lastName": "Example",
		"credentials": []map[string]any{{"type": "password", "value": password, "temporary": false}},
	}, http.StatusCreated)

	return password
}

// descriptor returns the realm's SAML IdP metadata.
func (k *kcAdmin) descriptor() []byte {
	k.t.Helper()

	resp, err := k.client.Get(k.base + "/realms/" + k.realm + "/protocol/saml/descriptor")
	require.NoError(k.t, err)

	defer resp.Body.Close()

	out, err := io.ReadAll(resp.Body)
	require.NoError(k.t, err)
	require.Equal(k.t, http.StatusOK, resp.StatusCode)

	return out
}

// importSP creates a client from SP metadata through Keycloak's converter
// (metadata exchange, SP to IdP) and returns its internal ID and attributes.
func (k *kcAdmin) importSP(metadata []byte) (string, map[string]string) {
	k.t.Helper()

	var rep map[string]any

	require.NoError(k.t, json.Unmarshal(k.do(http.MethodPost, "/admin/realms/"+k.realm+"/client-description-converter",
		metadata, http.StatusOK), &rep))

	k.do(http.MethodPost, "/admin/realms/"+k.realm+"/clients", rep, http.StatusCreated)

	clientID, _ := rep["clientId"].(string)

	var clients []map[string]any

	require.NoError(k.t, json.Unmarshal(k.do(http.MethodGet, "/admin/realms/"+k.realm+"/clients?clientId="+url.QueryEscape(clientID),
		nil, http.StatusOK), &clients))
	require.Len(k.t, clients, 1)

	attrs := map[string]string{}

	if raw, ok := clients[0]["attributes"].(map[string]any); ok {
		for name, v := range raw {
			if s, isString := v.(string); isString {
				attrs[name] = s
			}
		}
	}

	id, _ := clients[0]["id"].(string)

	return id, attrs
}

// setClientAttributes merges attributes into a client.
func (k *kcAdmin) setClientAttributes(id string, attrs map[string]string) {
	k.t.Helper()

	var rep map[string]any

	require.NoError(k.t, json.Unmarshal(k.do(http.MethodGet, "/admin/realms/"+k.realm+"/clients/"+id, nil, http.StatusOK), &rep))

	current, _ := rep["attributes"].(map[string]any)
	if current == nil {
		current = map[string]any{}
	}

	for name, v := range attrs {
		current[name] = v
	}

	rep["attributes"] = current
	k.do(http.MethodPut, "/admin/realms/"+k.realm+"/clients/"+id, rep, http.StatusNoContent)
}

// addRSAKey adds an active RS256 key provider with the given priority and
// returns its component ID.
func (k *kcAdmin) addRSAKey(name string, priority int) string {
	k.t.Helper()

	var realm map[string]any

	require.NoError(k.t, json.Unmarshal(k.do(http.MethodGet, "/admin/realms/"+k.realm, nil, http.StatusOK), &realm))

	k.do(http.MethodPost, "/admin/realms/"+k.realm+"/components", map[string]any{
		"name": name, "providerId": "rsa-generated", "providerType": "org.keycloak.keys.KeyProvider", "parentId": realm["id"],
		"config": map[string][]string{
			"priority": {fmt.Sprint(priority)}, "enabled": {"true"}, "active": {"true"}, "keySize": {"2048"}, "algorithm": {"RS256"},
		},
	}, http.StatusCreated)

	return k.componentID(name)
}

// componentID returns the ID of the key provider named name.
func (k *kcAdmin) componentID(name string) string {
	k.t.Helper()

	var comps []map[string]any

	require.NoError(k.t, json.Unmarshal(k.do(http.MethodGet, "/admin/realms/"+k.realm+"/components?type=org.keycloak.keys.KeyProvider",
		nil, http.StatusOK), &comps))

	for _, c := range comps {
		if c["name"] == name {
			id, _ := c["id"].(string)

			return id
		}
	}

	k.t.Fatalf("no key provider %q", name)

	return ""
}

// disableKey disables a key provider (its key leaves the descriptor).
func (k *kcAdmin) disableKey(id string) {
	k.t.Helper()

	var c map[string]any

	require.NoError(k.t, json.Unmarshal(k.do(http.MethodGet, "/admin/realms/"+k.realm+"/components/"+id, nil, http.StatusOK), &c))

	cfg, _ := c["config"].(map[string]any)
	cfg["enabled"] = []string{"false"}
	cfg["active"] = []string{"false"}
	k.do(http.MethodPut, "/admin/realms/"+k.realm+"/components/"+id, c, http.StatusNoContent)
}

// kcSP is the Service Provider side of one case: its own connection (SP
// entity ID and ACS), a recording store and a throwaway signing key that
// Keycloak trusts through the imported metadata.
type kcSP struct {
	t        *testing.T
	conn     samlsp.Connection
	key      testKey
	store    *recordingStore
	sp       *samlsp.ServiceProvider
	metadata []byte
}

func newKCSP(t *testing.T, name string, idpMetadata []byte, key testKey, nameIDFormat string) *kcSP {
	t.Helper()

	idp, err := samlsp.ParseIdentityProviderMetadata(idpMetadata, samlsp.MetadataOptions{})
	require.NoError(t, err)

	s := &kcSP{t: t, key: key, store: &recordingStore{Store: memory.New()}}
	s.conn = samlsp.Connection{
		ID: name, SPEntityID: "https://sp.example.test/saml/" + name, ACSURL: "https://sp.example.test/saml/" + name + "/acs",
		IdentityProvider: *idp, NameIDFormat: nameIDFormat,
	}
	s.rebuild(idpMetadata)

	return s
}

// rebuild re-imports the IdP metadata (as a metadata refresh would) and
// rebuilds the SP, keeping the store.
func (s *kcSP) rebuild(idpMetadata []byte) {
	s.t.Helper()

	idp, err := samlsp.ParseIdentityProviderMetadata(idpMetadata, samlsp.MetadataOptions{})
	require.NoError(s.t, err)

	s.conn.IdentityProvider = *idp
	conn := s.conn

	sp, err := samlsp.New(samlsp.Config{
		Connections: samlsp.ConnectionResolverFunc(func(_ context.Context, id string) (*samlsp.Connection, error) {
			if id != conn.ID {
				return nil, samlsp.ErrUnknownConnection
			}

			c := conn

			return &c, nil
		}),
		Transactions: s.store, ReplayCache: s.store,
		SigningKey: s.key.signer, SigningCertificate: s.key.cert,
		ClockSkew: liveClockSkew,
	})
	require.NoError(s.t, err)

	s.sp = sp

	md, err := sp.Metadata(context.Background(), conn.ID)
	require.NoError(s.t, err)

	s.metadata = md
}

// kcBrowser is a Go HTTP client with a cookie jar, as the browser of a
// Keycloak login.
type kcBrowser struct{ client *http.Client }

func newKCBrowser(t *testing.T) *kcBrowser {
	t.Helper()

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	return &kcBrowser{client: &http.Client{Jar: jar, Timeout: 30 * time.Second}}
}

// kcAttempt is one SP-initiated login up to Keycloak's POST form.
type kcAttempt struct {
	tx         samlsp.TransactionRecord
	cookie     string
	relayState string
	response   string // "" when Keycloak answered no form
	page       string // Keycloak's last page (diagnostics)
	at         time.Time
}

var (
	kcLoginForm = regexp.MustCompile(`<form[^>]+id="kc-form-login"[^>]+action="([^"]+)"`)
	kcField     = func(name string) *regexp.Regexp {
		return regexp.MustCompile(`(?i)name="` + name + `"\s+value="([^"]*)"`)
	}
)

// login runs BeginLogin, follows Keycloak, posts the credentials when it
// asks for them, and returns its HTTP-POST form.
func (s *kcSP) login(b *kcBrowser, opts samlsp.LoginOptions, user, password string) kcAttempt {
	s.t.Helper()

	rec := httptest.NewRecorder()
	target, err := s.sp.BeginLogin(context.Background(), rec, httptest.NewRequest(http.MethodGet, s.conn.SPEntityID, nil), s.conn.ID, opts)
	require.NoError(s.t, err)

	a := kcAttempt{tx: s.store.saved, at: time.Now().UTC().Truncate(time.Second)}

	for _, c := range rec.Result().Cookies() {
		a.cookie = c.Value
	}

	page := s.get(b, target)

	if m := kcLoginForm.FindSubmatch(page); m != nil {
		resp, err := b.client.PostForm(html.UnescapeString(string(m[1])),
			url.Values{"username": {user}, "password": {password}, "credentialId": {""}})
		require.NoError(s.t, err)

		page, err = io.ReadAll(resp.Body)
		require.NoError(s.t, err)
		require.NoError(s.t, resp.Body.Close())
	}

	a.page = string(page)

	if m := kcField("SAMLResponse").FindSubmatch(page); m != nil {
		a.response = html.UnescapeString(string(m[1]))
	}

	if m := kcField("RelayState").FindSubmatch(page); m != nil {
		a.relayState = html.UnescapeString(string(m[1]))
	}

	return a
}

func (s *kcSP) get(b *kcBrowser, u string) []byte {
	s.t.Helper()

	resp, err := b.client.Get(u)
	require.NoError(s.t, err)

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(s.t, err)

	return body
}

// complete posts the attempt to the SP's ACS.
func (s *kcSP) complete(a kcAttempt) (*samlsp.LoginResult, error) {
	s.t.Helper()

	form := url.Values{"SAMLResponse": {a.response}, "RelayState": {a.relayState}}
	req := httptest.NewRequest(http.MethodPost, s.conn.ACSURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: samlsp.DefaultCookieName, Value: a.cookie})

	return s.sp.CompleteLogin(context.Background(), req, s.conn.ID)
}

// throwawayCertificate returns a self-signed certificate (Keycloak client
// encryption certificate of the encrypted case; its key is discarded).
func throwawayCertificate(t *testing.T) string {
	t.Helper()

	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "throwaway"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	require.NoError(t, err)

	return base64.StdEncoding.EncodeToString(der)
}

// liveClockSkew is the SP clock skew of the live runs. goxmldsig checks
// the IdP certificate at now - ClockSkew, and Keycloak mints its realm (and
// rollover) certificates when they are created: with the default 3 minutes,
// a fresh certificate is refused for 3 minutes (LIMITATIONS.md, IdP
// certificate rollover). The live suite waits for its certificates to be
// liveClockSkew old instead.
const liveClockSkew = 10 * time.Second

// waitCertificates waits until every signing certificate of the IdP
// metadata is valid at now - liveClockSkew.
func waitCertificates(t *testing.T, metadata []byte) {
	t.Helper()

	idp, err := samlsp.ParseIdentityProviderMetadata(metadata, samlsp.MetadataOptions{})
	require.NoError(t, err)

	var newest time.Time

	for _, c := range idp.SigningCertificates {
		if c.NotBefore.After(newest) {
			newest = c.NotBefore
		}
	}

	if wait := time.Until(newest.Add(liveClockSkew + time.Second)); wait > 0 {
		t.Logf("waiting %s for the IdP certificate to be %s old", wait.Round(time.Second), liveClockSkew)
		time.Sleep(wait)
	}
}

// keycloakDir is the pinned capture directory of keycloakVersion.
var keycloakDir26 = filepath.Join("testdata", "keycloak-"+keycloakVersion)

// TestKeycloakLive runs the SP against a live Keycloak (opt-in).
func TestKeycloakLive(t *testing.T) {
	base := os.Getenv("SAMLSP_KEYCLOAK_URL")
	if base == "" {
		t.Skip("set SAMLSP_KEYCLOAK_URL and SAMLSP_KEYCLOAK_ADMIN_PASSWORD (compose.yaml) to run Keycloak live")
	}

	k := newKCAdmin(t, base)

	var info struct {
		SystemInfo struct {
			Version string `json:"version"`
		} `json:"systemInfo"`
	}

	require.NoError(t, json.Unmarshal(k.do(http.MethodGet, "/admin/serverinfo", nil, http.StatusOK), &info))
	t.Logf("Keycloak %s", info.SystemInfo.Version)
	require.Equal(t, keycloakVersion, info.SystemInfo.Version, "compose.yaml pins %s", keycloakVersion)

	password := k.setUp("alice", "alice@example.com")
	descriptor := k.descriptor()
	waitCertificates(t, descriptor)

	var cases []keycloakCase

	record := func(name, about string, s *kcSP, a kcAttempt, metadata []byte, clientID string, expect keycloakExpect) {
		var client map[string]any

		require.NoError(t, json.Unmarshal(k.do(http.MethodGet, "/admin/realms/"+k.realm+"/clients/"+clientID, nil, http.StatusOK), &client))

		settings := map[string]string{}

		if attrs, ok := client["attributes"].(map[string]any); ok {
			for _, name := range allowedClientSettings {
				if v, isString := attrs[name].(string); isString {
					settings[name] = v
				}
			}
		}

		cases = append(cases, keycloakCase{
			Name: name, About: about, CapturedAt: a.at, Metadata: string(metadata),
			Connection: keycloakConnection{ID: s.conn.ID, SPEntityID: s.conn.SPEntityID, ACSURL: s.conn.ACSURL},
			Client:     settings, Transaction: a.tx, Cookie: a.cookie, RelayState: a.relayState, Response: a.response,
			Expect: expect,
		})
	}

	// newCase builds an SP connection, registers it at Keycloak through
	// its metadata, and applies the client settings of the case.
	newCase := func(name string, settings map[string]string) (*kcSP, string) {
		// The SP requests (and publishes) persistent NameIDs, as the guide
		// recommends, unless the case forces another format at the IdP.
		format := samlsp.NameIDFormatPersistent
		if settings["saml_force_name_id_format"] == "true" {
			format = ""
		}

		s := newKCSP(t, name, descriptor, newKey(t, "sp-"+name), format)
		id, imported := k.importSP(s.metadata)

		// K1: Keycloak read our SP metadata.
		require.Equal(t, s.conn.ACSURL, imported["saml_assertion_consumer_url_post"])
		require.Equal(t, "true", imported["saml.client.signature"], "AuthnRequestsSigned honoured")
		require.Equal(t, base64.StdEncoding.EncodeToString(s.key.cert.Raw), imported["saml.signing.certificate"])
		require.NotEqual(t, "true", imported["saml.encrypt"], "no encryption key published, none configured")

		if len(settings) > 0 {
			k.setClientAttributes(id, settings)
		}

		return s, id
	}

	t.Run("K1 metadata exchange", func(t *testing.T) {
		idp, err := samlsp.ParseIdentityProviderMetadata(descriptor, samlsp.MetadataOptions{})
		require.NoError(t, err)
		require.True(t, idp.WantAuthnRequestsSigned)
		require.Equal(t, base+"/realms/"+k.realm, idp.EntityID)
	})

	accepted := func(t *testing.T, s *kcSP, a kcAttempt) *samlsp.LoginResult {
		t.Helper()
		require.NotEmpty(t, a.response, "Keycloak answered no form: %.300s", a.page)

		res, err := s.complete(a)
		require.NoError(t, err)

		return res
	}

	// K2 + K6: signature placements and algorithms.
	for _, c := range []struct {
		name, about string
		settings    map[string]string
		expect      keycloakExpect
	}{
		{"response-signed", "Keycloak default after importing our metadata: the document is signed (errata E26/E93)",
			map[string]string{"saml.server.signature": "true", "saml.assertion.signature": "false"},
			keycloakExpect{NameIDFormat: samlsp.NameIDFormatPersistent}},
		{"assertion-signed", "only the assertion is signed",
			map[string]string{"saml.server.signature": "false", "saml.assertion.signature": "true"},
			keycloakExpect{NameIDFormat: samlsp.NameIDFormatPersistent}},
		{"both-signed", "document and assertion signed",
			map[string]string{"saml.server.signature": "true", "saml.assertion.signature": "true"},
			keycloakExpect{NameIDFormat: samlsp.NameIDFormatPersistent}},
		{"unsigned", "neither the document nor the assertion is signed",
			map[string]string{"saml.server.signature": "false", "saml.assertion.signature": "false"},
			keycloakExpect{Error: "ErrInvalidSignature", Detail: "neither the Response nor the Assertion is signed"}},
		{"rsa-sha1", "RSA_SHA1 signatures: refused without the opt-in",
			map[string]string{"saml.server.signature": "true", "saml.assertion.signature": "true", "saml.signature.algorithm": "RSA_SHA1"},
			keycloakExpect{Error: "ErrUnsupportedAlgorithm", WithSHA1OptIn: "accepted"}},
		{"rsa-pss", "RSA_SHA256_MGF1 (RSASSA-PSS) signatures: not in the allowlist",
			map[string]string{"saml.server.signature": "true", "saml.signature.algorithm": "RSA_SHA256_MGF1"},
			keycloakExpect{Error: "ErrUnsupportedAlgorithm"}},
		{"encrypted", "EncryptedAssertion (client encryption certificate configured by hand)",
			map[string]string{"saml.encrypt": "true", "saml.encryption.certificate": throwawayCertificate(t)},
			keycloakExpect{Error: "ErrEncryptedAssertionUnsupported"}},
		{"transient-nameid", "transient NameID: reported as is, never an account key",
			map[string]string{"saml_force_name_id_format": "true", "saml_name_id_format": "transient"},
			keycloakExpect{NameIDFormat: samlsp.NameIDFormatTransient}},
		{"email-nameid", "email NameID: reported as is, never linked by email",
			map[string]string{"saml_force_name_id_format": "true", "saml_name_id_format": "email"},
			keycloakExpect{NameIDFormat: samlsp.NameIDFormatEmailAddress, NameIDValue: "alice@example.com"}},
		{"username-nameid", "username NameID (unspecified format)",
			map[string]string{"saml_force_name_id_format": "true", "saml_name_id_format": "username"},
			keycloakExpect{NameIDFormat: samlsp.NameIDFormatUnspecified, NameIDValue: "alice"}},
	} {
		t.Run("K6 "+c.name, func(t *testing.T) {
			s, id := newCase(c.name, c.settings)
			a := s.login(newKCBrowser(t), samlsp.LoginOptions{AppState: "/" + c.name}, "alice", password)
			require.NotEmpty(t, a.response, "Keycloak answered no form: %.300s", a.page)

			res, err := s.complete(a)
			requireOutcome(t, c.expect, c.about, res, err)

			record(c.name, c.about, s, a, descriptor, id, c.expect)
		})
	}

	// K7: statuses and freshness.
	t.Run("K7 IsPassive without a session", func(t *testing.T) {
		s, id := newCase("no-passive", nil)
		a := s.login(newKCBrowser(t), samlsp.LoginOptions{IsPassive: true, AppState: "/passive"}, "alice", password)
		require.NotEmpty(t, a.response, "Keycloak answered no form: %.300s", a.page)

		_, err := s.complete(a)

		var se *samlsp.StatusError
		require.ErrorAs(t, err, &se)
		t.Logf("IsPassive without a session: %s / %s", se.Code, se.SubCode)
		require.Equal(t, "/passive", se.AppState)

		record("no-passive", "IsPassive without an IdP session: an error status, bound to the transaction", s, a, descriptor, id,
			keycloakExpect{Error: "ErrResponseStatus", StatusCode: se.Code, StatusSubCode: se.SubCode})
	})

	t.Run("K7 ForceAuthn with an IdP session", func(t *testing.T) {
		s, id := newCase("force-authn", nil)
		b := newKCBrowser(t)
		_ = accepted(t, s, s.login(b, samlsp.LoginOptions{}, "alice", password))

		time.Sleep(1100 * time.Millisecond) // AuthnInstant has a one-second resolution
		a := s.login(b, samlsp.LoginOptions{ForceAuthn: true}, "alice", password)
		res := accepted(t, s, a)
		require.False(t, res.Identity.AuthnInstant.Before(a.at), "a fresh authentication")

		record("force-authn", "ForceAuthn with an IdP session: Keycloak authenticates again", s, a, descriptor, id,
			keycloakExpect{NameIDFormat: samlsp.NameIDFormatPersistent})
	})

	// K3: Keycloak verifies the redirect signature.
	t.Run("K3 signed AuthnRequests", func(t *testing.T) {
		s, _ := newCase("request-signing", nil)
		accepted(t, s, s.login(newKCBrowser(t), samlsp.LoginOptions{}, "alice", password))

		// A key Keycloak does not know: it answers no response.
		s.key = newKey(t, "unregistered")
		s.rebuild(descriptor)

		a := s.login(newKCBrowser(t), samlsp.LoginOptions{}, "alice", password)
		require.Empty(t, a.response, "Keycloak must refuse a request signed by an unregistered key")

		// No SP key while Keycloak wants signed requests: fail closed.
		unsigned, err := samlsp.New(samlsp.Config{
			Connections: samlsp.ConnectionResolverFunc(func(context.Context, string) (*samlsp.Connection, error) {
				c := s.conn

				return &c, nil
			}),
			Transactions: memory.New(), ReplayCache: memory.New(),
		})
		require.NoError(t, err)

		_, err = unsigned.BeginLogin(context.Background(), httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil),
			s.conn.ID, samlsp.LoginOptions{})
		require.ErrorIs(t, err, samlsp.ErrInvalidConfig)
	})

	// K5: SP signing-key rollover with a client that pins one certificate.
	t.Run("K5 SP key rollover", func(t *testing.T) {
		s, id := newCase("sp-rollover", nil)
		next := newKey(t, "sp-next")

		// Switch the SP before the IdP learnt the new key: refused.
		s.key = next
		s.rebuild(descriptor)

		a := s.login(newKCBrowser(t), samlsp.LoginOptions{}, "alice", password)
		require.Empty(t, a.response, "the client still pins the previous certificate")

		// Runbook step: re-import the SP metadata (one certificate per client).
		k.setClientAttributes(id, map[string]string{"saml.signing.certificate": base64.StdEncoding.EncodeToString(next.cert.Raw)})
		accepted(t, s, s.login(newKCBrowser(t), samlsp.LoginOptions{}, "alice", password))
	})

	// K4: IdP key rollover, last (it changes the realm keys).
	t.Run("K4 IdP key rollover", func(t *testing.T) {
		s, id := newCase("idp-rollover", nil)
		b := newKCBrowser(t)

		// A response signed by the current key, kept for later.
		old := s.login(b, samlsp.LoginOptions{AppState: "/old"}, "alice", password)
		require.NotEmpty(t, old.response)

		// Announce and use a new key; the SP refreshes the metadata.
		k.addRSAKey("rollover", 200)
		both := k.descriptor()
		waitCertificates(t, both)
		s.rebuild(both)
		require.Len(t, s.conn.IdentityProvider.SigningCertificates, 2, "both keys announced")

		a := s.login(b, samlsp.LoginOptions{}, "alice", password)
		accepted(t, s, a)
		record("idp-rollover-new-key", "IdP key rollover: the new key signs while both are announced", s, a, both, id,
			keycloakExpect{NameIDFormat: samlsp.NameIDFormatPersistent})

		// Retire the old key; after the refresh its responses are refused.
		k.disableKey(k.componentID("rsa-generated"))
		retired := k.descriptor()
		s.rebuild(retired)
		require.Len(t, s.conn.IdentityProvider.SigningCertificates, 1)

		_, err := s.complete(old)
		require.ErrorIs(t, err, samlsp.ErrInvalidSignature)
		record("idp-rollover-retired-key", "IdP key rollover: a response of the retired key after the refresh", s, old, retired, id,
			keycloakExpect{Error: "ErrInvalidSignature", Detail: "signature verification failed"})
	})

	if *captureKeycloak {
		require.NoError(t, os.MkdirAll(keycloakDir26, 0o750))

		for _, c := range cases {
			out, err := json.MarshalIndent(c, "", "  ")
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(keycloakDir26, c.Name+".json"), append(out, '\n'), 0o600))
		}

		t.Logf("captured %d cases in %s", len(cases), keycloakDir26)
	}
}

// keycloakSentinel maps a sentinel name of a case.
func keycloakSentinel(t *testing.T, name string) error {
	t.Helper()

	sentinels := map[string]error{
		"ErrInvalidSignature": samlsp.ErrInvalidSignature, "ErrUnsupportedAlgorithm": samlsp.ErrUnsupportedAlgorithm,
		"ErrEncryptedAssertionUnsupported": samlsp.ErrEncryptedAssertionUnsupported, "ErrResponseStatus": samlsp.ErrResponseStatus,
	}

	err, ok := sentinels[name]
	require.True(t, ok, "unknown sentinel %s", name)

	return err
}
