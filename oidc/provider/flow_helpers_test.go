// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/hyperscale-stack/security/oauth2"
	oidcprovider "github.com/hyperscale-stack/security/oidc/provider"
	"github.com/stretchr/testify/require"
)

const testNonce = "n-0S6_WzA2Mj"

// authorizeQuery is a valid OpenID Connect request of the web client: code
// flow, S256 PKCE, a nonce.
func authorizeQuery() url.Values {
	return url.Values{
		"response_type": {"code"}, "client_id": {webClientID}, "redirect_uri": {webRedirectURI},
		"scope": {"openid profile email"}, "state": {"st-1"}, "nonce": {testNonce},
		"code_challenge": {pkceChallenge}, "code_challenge_method": {"S256"},
	}
}

// with returns a copy of q with key set to value ("" deletes it).
func with(q url.Values, kv ...string) url.Values {
	out := url.Values{}
	for k, v := range q {
		out[k] = append([]string(nil), v...)
	}

	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "" {
			out.Del(kv[i])

			continue
		}

		out.Set(kv[i], kv[i+1])
	}

	return out
}

// authorize runs GET /authorize through the provider's handler.
func (e *env) authorize(q url.Values) *httptest.ResponseRecorder {
	return e.authorizeWith(oauth2.AuthorizeConfig{}, q)
}

func (e *env) authorizeWith(cfg oauth2.AuthorizeConfig, q url.Values) *httptest.ResponseRecorder {
	return serve(e.op.AuthorizeHandler(cfg), get("/oauth2/authorize?"+q.Encode()))
}

// redirect returns the parameters of an authorization response.
func redirect(t *testing.T, rec *httptest.ResponseRecorder) url.Values {
	t.Helper()

	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())

	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)

	if loc.Fragment != "" {
		params, err := url.ParseQuery(loc.Fragment)
		require.NoError(t, err)

		return params
	}

	return loc.Query()
}

// code runs /authorize and returns the issued code.
func (e *env) code(q url.Values) string {
	e.t.Helper()

	params := redirect(e.t, e.authorize(q))
	require.Empty(e.t, params.Get("error"), params.Get("error_description"))
	require.NotEmpty(e.t, params.Get("code"))

	return params.Get("code")
}

// token posts form to /token, authenticated as clientID with Basic (the
// credentials form-encoded, RFC 6749 §2.3.1).
func (e *env) token(form url.Values, clientID string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(webClientSecret))

	return serve(e.op.Server().TokenHandler(), r)
}

// exchange redeems code as the web client with the canonical verifier.
func (e *env) exchange(code string) *httptest.ResponseRecorder {
	return e.exchangeAs(code, webClientID)
}

func (e *env) exchangeAs(code, clientID string) *httptest.ResponseRecorder {
	return e.token(url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {webRedirectURI}, "code_verifier": {pkceVerifier},
	}, clientID)
}

// refresh exchanges rt, narrowing the scope when scope is non-empty.
func (e *env) refresh(rt, scope string) *httptest.ResponseRecorder {
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}
	if scope != "" {
		form.Set("scope", scope)
	}

	return e.token(form, webClientID)
}

// tokenResponse is a decoded successful token response.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token"`
}

// tokens decodes a successful token response.
func tokens(t *testing.T, rec *httptest.ResponseRecorder) tokenResponse {
	t.Helper()

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var out tokenResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))

	return out
}

// oauthError returns the error member of an error response.
func oauthError(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body), rec.Body.String())

	code, _ := body["error"].(string)

	return code
}

// flow runs the whole code flow of q and returns the token response.
func (e *env) flow(q url.Values) tokenResponse {
	e.t.Helper()

	return tokens(e.t, e.exchange(e.code(q)))
}

// verificationKeys returns every verification key of the current ring.
func (e *env) verificationKeys() []jwtsec.PublicKey {
	ring, err := e.keys.Keys(context.Background(), testIssuer)
	must(err)

	var out []jwtsec.PublicKey
	for _, k := range ring.Signing {
		out = append(out, publicOf(k))
	}

	return append(out, ring.Published...)
}

// idToken verifies the signature of raw against the ring's keys and
// returns its header and claims.
func (e *env) idToken(raw string) (header, claims map[string]any) {
	e.t.Helper()

	return decodeJWT(e.t, raw, e.verificationKeys())
}

func decodeJWT(t *testing.T, raw string, keys []jwtsec.PublicKey) (header, claims map[string]any) {
	t.Helper()

	require.NotEmpty(t, raw, "an ID Token is expected")

	verified, err := jwtsec.VerifySignature(context.Background(), raw, keys)
	require.NoError(t, err)

	headerJSON, err := base64.RawURLEncoding.DecodeString(strings.SplitN(raw, ".", 2)[0])
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(headerJSON, &header))

	dec := json.NewDecoder(strings.NewReader(string(verified.Payload)))
	dec.UseNumber()
	require.NoError(t, dec.Decode(&claims))

	return header, claims
}

// unix reads a NumericDate claim.
func unix(t *testing.T, v any) int64 {
	t.Helper()

	n, ok := v.(json.Number)
	require.True(t, ok, "%v is a JSON number", v)

	i, err := n.Int64()
	require.NoError(t, err)

	return i
}

// approveWith scripts the interactive and silent paths to return d,
// completed with the request's issuer when its authentication names none.
func (e *env) approveWith(d func(req *oidcprovider.Request) *oidcprovider.Decision) {
	e.interaction.script(func(_ http.ResponseWriter, _ *http.Request, req *oidcprovider.Request) (*oidcprovider.Decision, error) {
		return d(req), nil
	})
	e.interaction.scriptSilent(func(_ *http.Request, req *oidcprovider.Request) (*oidcprovider.Decision, error) {
		return d(req), nil
	})
}

// event is the authentication of alice within req's issuer, at the clock's
// now.
func (e *env) event(req *oidcprovider.Request) *oidcprovider.AuthenticationEvent {
	return &oidcprovider.AuthenticationEvent{Issuer: req.Issuer, Subject: "alice", AuthTime: e.clock.Now(), AMR: []string{"pwd"}}
}
