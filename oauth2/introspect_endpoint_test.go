// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/clientauth"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/hyperscale-stack/security/oauth2/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Clients registered on the introspection test server (see
// introspectClients).
const (
	spaClientID          = "spa"
	rsAPIClientID        = "rs-api"
	rsAPISecret          = "rs-api-secret"
	rsBillingClientID    = "rs-billing"
	rsBillingSecret      = "rs-billing-secret"
	publicSecretClientID = "public-with-secret"
	publicSecret         = "public-secret"
	untypedClientID      = "untyped"
	untypedSecret        = "untyped-secret"
	untypedNoSecretID    = "untyped-no-secret"
)

const (
	// introspectionRefused is the error_description /introspect answers
	// every caller that is not a confidential client with.
	introspectionRefused = "introspection requires confidential client authentication"
	// inactiveBody is the bare RFC 7662 §2.2 answer for a token the caller
	// may not see.
	inactiveBody = `{"active":false}`
)

// The instant the introspection test server's clock is pinned to, and the
// timestamps of the active tokens seedTokens persists.
var (
	introspectNow    = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	seededIssuedAt   = introspectNow.Add(-time.Minute)
	seededAccessExp  = introspectNow.Add(time.Hour)
	seededRefreshExp = introspectNow.Add(24 * time.Hour)
)

// descriptionCharset is the RFC 6749 §5.2 error_description charset:
// %x20-21 / %x23-5B / %x5D-7E — no double quote, no backslash.
var descriptionCharset = regexp.MustCompile(`^[\x20-\x21\x23-\x5B\x5D-\x7E]*$`)

// introspectClients registers the callers the introspection tests use.
// AuthMethodValues stays empty (any method) everywhere, so a refusal can
// only come from the endpoint's own caller check.
func introspectClients() *staticClientStore {
	return &staticClientStore{clients: map[string]oauth2.Client{
		// A public SPA: "none" + PKCE at /token.
		spaClientID: &oauth2.DefaultClient{
			IDValue:           spaClientID,
			TypeValue:         oauth2.ClientPublic,
			RedirectURIValues: []string{redirectURI},
			ScopeValues:       []string{"read"},
		},
		// Two confidential resource servers.
		rsAPIClientID: &oauth2.DefaultClient{
			IDValue: rsAPIClientID, Secret: rsAPISecret, TypeValue: oauth2.ClientConfidential,
		},
		rsBillingClientID: &oauth2.DefaultClient{
			IDValue: rsBillingClientID, Secret: rsBillingSecret, TypeValue: oauth2.ClientConfidential,
		},
		// A public client provisioned with a secret all the same.
		publicSecretClientID: &oauth2.DefaultClient{
			IDValue: publicSecretClientID, Secret: publicSecret, TypeValue: oauth2.ClientPublic,
		},
		// Clients with no declared type, with and without a secret.
		untypedClientID:   &oauth2.DefaultClient{IDValue: untypedClientID, Secret: untypedSecret},
		untypedNoSecretID: &oauth2.DefaultClient{IDValue: untypedNoSecretID},
	}}
}

// newIntrospectServer builds a Profile20BCP server pinned to introspectNow.
// It serves /authorize, /token (authorization_code + rotating
// refresh_token), /revoke and /introspect, authenticates clients with
// client_secret_basic, client_secret_post and none, and holds the
// seedTokens tokens. policy and onError may be nil.
func newIntrospectServer(t *testing.T, policy oauth2.IntrospectionPolicy, onError oauth2.ErrorHook) *oauth2.Server {
	t.Helper()

	store := memory.New()
	gcfg := grant.Config{
		Storage:             store,
		AccessTokens:        token.NewOpaque(32),
		RefreshTokens:       token.OpaqueRefreshAdapter{Opaque: token.NewOpaque(32)},
		AccessTTL:           time.Hour,
		RefreshTTL:          24 * time.Hour,
		RotateRefreshTokens: true,
	}

	srv, err := oauth2.NewServer(oauth2.ServerConfig{
		Profile:        oauth2.Profile20BCP,
		Storage:        store,
		ClientStore:    introspectClients(),
		IssuerResolver: oauth2.StaticIssuer("https://auth.example", "api"),
		Grants:         []oauth2.Grant{grant.NewAuthorizationCode(gcfg), grant.NewRefreshToken(gcfg)},
		ClientAuth: []oauth2.ClientAuthenticator{
			clientauth.NewBasic(), clientauth.NewPost(), clientauth.NewNone(),
		},
		Now:                 func() time.Time { return introspectNow },
		OnError:             onError,
		IntrospectionPolicy: policy,
	})
	require.NoError(t, err)

	seedTokens(t, store)

	return srv
}

// seedTokens persists the tokens the introspection tests look up, all
// issued to the "app" client — which no test caller is. It is the only
// direct store write of this file, and each refresh token sits next to an
// access token of its own family, as a grant issues them:
//
//   - at-app / rt-app (fam-app): active, for alice, scope read, audience api.
//   - at-expired / rt-expired (fam-expired): past their expiry.
//   - at-consumed / rt-consumed (fam-consumed): the refresh token was
//     already rotated, into at-consumed-next / rt-consumed-next.
func seedTokens(t *testing.T, store *memory.Store) {
	t.Helper()

	expiredAt := introspectNow.Add(-time.Hour)
	pairs := []struct {
		access  oauth2.AccessToken
		refresh oauth2.RefreshToken
	}{
		{
			access: oauth2.AccessToken{
				TokenHash: oauth2.HashToken(nil, "at-app"), ClientID: "app", Subject: "alice", Scope: "read",
				Audience: "api", FamilyID: "fam-app", IssuedAt: seededIssuedAt, ExpiresAt: seededAccessExp,
			},
			refresh: oauth2.RefreshToken{
				TokenHash: oauth2.HashToken(nil, "rt-app"), ClientID: "app", Subject: "alice", Scope: "read",
				FamilyID: "fam-app", IssuedAt: seededIssuedAt, ExpiresAt: seededRefreshExp,
			},
		},
		{
			access: oauth2.AccessToken{
				TokenHash: oauth2.HashToken(nil, "at-expired"), ClientID: "app", Subject: "alice", Scope: "read",
				Audience: "api", FamilyID: "fam-expired", IssuedAt: expiredAt.Add(-time.Hour), ExpiresAt: expiredAt,
			},
			refresh: oauth2.RefreshToken{
				TokenHash: oauth2.HashToken(nil, "rt-expired"), ClientID: "app", Subject: "alice", Scope: "read",
				FamilyID: "fam-expired", IssuedAt: expiredAt.Add(-time.Hour), ExpiresAt: expiredAt,
			},
		},
		{
			access: oauth2.AccessToken{
				TokenHash: oauth2.HashToken(nil, "at-consumed"), ClientID: "app", Subject: "alice", Scope: "read",
				Audience: "api", FamilyID: "fam-consumed", IssuedAt: seededIssuedAt, ExpiresAt: seededAccessExp,
			},
			refresh: oauth2.RefreshToken{
				TokenHash: oauth2.HashToken(nil, "rt-consumed"), ClientID: "app", Subject: "alice", Scope: "read",
				FamilyID: "fam-consumed", IssuedAt: seededIssuedAt, ExpiresAt: seededRefreshExp,
			},
		},
	}

	for _, p := range pairs {
		require.NoError(t, store.SaveTokenPair(t.Context(), &oauth2.TokenPair{Access: p.access, Refresh: &p.refresh}))
	}

	// A refresh token is only ever consumed by a rotation.
	require.NoError(t, store.RotateRefreshToken(t.Context(), oauth2.HashToken(nil, "rt-consumed"), &oauth2.TokenPair{
		Access: oauth2.AccessToken{
			TokenHash: oauth2.HashToken(nil, "at-consumed-next"), ClientID: "app", Subject: "alice", Scope: "read",
			Audience: "api", FamilyID: "fam-consumed", IssuedAt: seededIssuedAt, ExpiresAt: seededAccessExp,
		},
		Refresh: &oauth2.RefreshToken{
			TokenHash: oauth2.HashToken(nil, "rt-consumed-next"), ClientID: "app", Subject: "alice", Scope: "read",
			FamilyID: "fam-consumed", IssuedAt: seededIssuedAt, ExpiresAt: seededRefreshExp,
		},
	}))
}

// basicForm builds a form POST authenticated with HTTP Basic as id:secret
// (formRequest can only authenticate as client-abc).
func basicForm(path string, form url.Values, id, secret string) *http.Request {
	req := formRequest(path, form, false)
	req.SetBasicAuth(id, secret)

	return req
}

// introspectRequest asks /introspect about raw, authenticated with HTTP
// Basic as id:secret.
func introspectRequest(id, secret, raw string) *http.Request {
	return basicForm("/oauth2/introspect", url.Values{"token": {raw}}, id, secret)
}

// serve runs req through h and returns the recorded response.
func serve(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	return rec
}

// decodeBody decodes a JSON response body.
func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))

	return body
}

// assertAnswersLikeUnknown asserts that the /introspect answer rec, about
// the token raw, is exactly the one unknown got for a never-issued token —
// same status, headers and bytes (RFC 7662 §2.2) — so it discloses nothing.
func assertAnswersLikeUnknown(t *testing.T, unknown, rec *httptest.ResponseRecorder, raw string) {
	t.Helper()

	assert.Equal(t, http.StatusOK, rec.Code, raw)
	assert.JSONEq(t, inactiveBody, rec.Body.String(), raw)
	assert.Equal(t, unknown.Body.Bytes(), rec.Body.Bytes(), raw)
	assert.Equal(t, unknown.Header(), rec.Header(), raw)
}

// policyProbe is an [oauth2.IntrospectionPolicy] double: it answers allow
// and err, and counts its calls.
type policyProbe struct {
	allow bool
	err   error
	calls atomic.Int32
}

func (p *policyProbe) decide(context.Context, oauth2.Client, oauth2.IntrospectedToken) (bool, error) {
	p.calls.Add(1)

	return p.allow, p.err
}

// TestIntrospectCallerAuthentication covers the endpoint authentication
// RFC 7662 §2.1 / §4 require: only a confidential client is answered. Any
// other caller — a public client whatever the method, an untyped client, a
// failed authentication — gets 401 invalid_client before the token is
// looked at.
func TestIntrospectCallerAuthentication(t *testing.T) {
	t.Parallel()

	// postForm builds an /introspect request for the active at-app token,
	// carrying credentials (if any) in the form only.
	postForm := func(credentials url.Values) *http.Request {
		form := url.Values{"token": {"at-app"}}
		for k, v := range credentials {
			form[k] = v
		}

		return formRequest("/oauth2/introspect", form, false)
	}

	cases := []struct {
		name     string
		req      *http.Request
		accepted bool
		wantDesc string // the pinned error_description, if any
	}{
		{
			name:     "client_secret_basic confidential client",
			req:      introspectRequest(rsAPIClientID, rsAPISecret, "at-app"),
			accepted: true,
		},
		{
			name:     "client_secret_post confidential client",
			req:      postForm(url.Values{"client_id": {rsAPIClientID}, "client_secret": {rsAPISecret}}),
			accepted: true,
		},
		{
			name:     "none public client",
			req:      postForm(url.Values{"client_id": {spaClientID}}),
			wantDesc: introspectionRefused,
		},
		{
			name: "none unknown client",
			req:  postForm(url.Values{"client_id": {"ghost"}}),
		},
		{
			name:     "none confidential client",
			req:      postForm(url.Values{"client_id": {rsAPIClientID}}),
			wantDesc: "none method reserved to public clients",
		},
		{
			name:     "basic public client with an empty password",
			req:      introspectRequest(spaClientID, "", "at-app"),
			wantDesc: introspectionRefused,
		},
		{
			name:     "basic public client with a secret",
			req:      introspectRequest(publicSecretClientID, publicSecret, "at-app"),
			wantDesc: introspectionRefused,
		},
		{
			name:     "post public client with a secret",
			req:      postForm(url.Values{"client_id": {publicSecretClientID}, "client_secret": {publicSecret}}),
			wantDesc: introspectionRefused,
		},
		{
			name:     "basic untyped client",
			req:      introspectRequest(untypedClientID, untypedSecret, "at-app"),
			wantDesc: introspectionRefused,
		},
		{
			name:     "basic untyped client with an empty password",
			req:      introspectRequest(untypedNoSecretID, "", "at-app"),
			wantDesc: introspectionRefused,
		},
		{
			name: "wrong secret",
			req:  introspectRequest(rsAPIClientID, "wrong", "at-app"),
		},
		{
			name: "no credentials",
			req:  postForm(nil),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			probe := &policyProbe{allow: true}
			sink := &errorSink{}
			srv := newIntrospectServer(t, probe.decide, sink.hook)

			rec := serve(srv.IntrospectHandler(), tc.req)
			body := decodeBody(t, rec)

			if tc.accepted {
				require.Equal(t, http.StatusOK, rec.Code)
				assert.Equal(t, true, body["active"])
				assert.Equal(t, int32(1), probe.calls.Load())
				assert.Empty(t, sink.codes())

				return
			}

			// RFC 7662 §2.3 / RFC 6749 §5.2: a failed endpoint
			// authentication is a 401 invalid_client with a challenge...
			require.Equal(t, http.StatusUnauthorized, rec.Code)
			assert.NotEmpty(t, rec.Header().Get("WWW-Authenticate"))
			assert.Equal(t, oauth2.CodeInvalidClient, body["error"])

			desc, _ := body["error_description"].(string)
			assert.Regexp(t, descriptionCharset, desc)

			if tc.wantDesc != "" {
				assert.Equal(t, tc.wantDesc, desc)
			}

			// ...that tells nothing about the token, never handed to the
			// policy.
			assert.NotContains(t, body, "active")
			assert.NotContains(t, body, "sub")
			assert.NotContains(t, body, "scope")
			assert.Zero(t, probe.calls.Load(), "the policy must not run for a refused caller")
			assert.Equal(t, []string{oauth2.CodeInvalidClient}, sink.codes())
		})
	}
}

// TestIntrospectDefaultDisclosesToConfidentialResourceServer pins the
// default: with no policy, any authenticated confidential client sees any
// token — including one issued to another client, since the resource
// server asking is usually not the client the token was issued to.
func TestIntrospectDefaultDisclosesToConfidentialResourceServer(t *testing.T) {
	t.Parallel()

	srv := newIntrospectServer(t, nil, nil)

	rec := serve(srv.IntrospectHandler(), introspectRequest(rsBillingClientID, rsBillingSecret, "at-app"))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, fmt.Sprintf(
		`{"active":true,"scope":"read","client_id":"app","sub":"alice","exp":%d,"iat":%d,"token_type":"Bearer","aud":"api"}`,
		seededAccessExp.Unix(), seededIssuedAt.Unix()), rec.Body.String())

	rec = serve(srv.IntrospectHandler(), introspectRequest(rsBillingClientID, rsBillingSecret, "rt-app"))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, fmt.Sprintf(
		`{"active":true,"scope":"read","client_id":"app","sub":"alice","exp":%d,"iat":%d,"token_type":"refresh_token"}`,
		seededRefreshExp.Unix(), seededIssuedAt.Unix()), rec.Body.String())
}

// tenantKey carries a request-scoped tenant, as a middleware would set it.
type tenantKey struct{}

// TestIntrospectionPolicyInputs checks what the policy is handed: the
// request context, the authenticated caller as the ClientStore returned
// it, and the token's metadata — never its value.
func TestIntrospectionPolicyInputs(t *testing.T) {
	t.Parallel()

	type call struct {
		tenant any
		caller oauth2.Client
		token  oauth2.IntrospectedToken
	}

	var calls []call

	srv := newIntrospectServer(t,
		func(ctx context.Context, caller oauth2.Client, tok oauth2.IntrospectedToken) (bool, error) {
			calls = append(calls, call{tenant: ctx.Value(tenantKey{}), caller: caller, token: tok})

			return true, nil
		}, nil)

	for _, raw := range []string{"at-app", "rt-app"} {
		req := introspectRequest(rsAPIClientID, rsAPISecret, raw)
		req = req.WithContext(context.WithValue(req.Context(), tenantKey{}, "tenant-a"))

		rec := serve(srv.IntrospectHandler(), req)
		require.Equal(t, http.StatusOK, rec.Code, raw)
		assert.Equal(t, true, decodeBody(t, rec)["active"], raw)
	}

	require.Len(t, calls, 2)

	for _, c := range calls {
		assert.Equal(t, "tenant-a", c.tenant, "the policy sees the request context")
		assert.IsType(t, &oauth2.DefaultClient{}, c.caller, "the caller is the ClientStore record")
		assert.Equal(t, rsAPIClientID, c.caller.ID())
		assert.Equal(t, oauth2.ClientConfidential, c.caller.Type())
	}

	assert.Equal(t, oauth2.IntrospectedToken{
		Kind:      oauth2.TokenKindAccess,
		ClientID:  "app",
		Subject:   "alice",
		Scope:     "read",
		Audience:  "api",
		IssuedAt:  seededIssuedAt,
		ExpiresAt: seededAccessExp,
	}, calls[0].token)

	// A refresh token carries no audience.
	assert.Equal(t, oauth2.IntrospectedToken{
		Kind:      oauth2.TokenKindRefresh,
		ClientID:  "app",
		Subject:   "alice",
		Scope:     "read",
		IssuedAt:  seededIssuedAt,
		ExpiresAt: seededRefreshExp,
	}, calls[1].token)
}

// TestIntrospectionPolicyNotConsultedForInactiveTokens: an unknown,
// expired or consumed token answers {"active":false} on its own — the
// policy only ever sees active tokens.
func TestIntrospectionPolicyNotConsultedForInactiveTokens(t *testing.T) {
	t.Parallel()

	probe := &policyProbe{allow: true}
	srv := newIntrospectServer(t, probe.decide, nil)

	for _, raw := range []string{"ghost", "at-expired", "rt-expired", "rt-consumed"} {
		rec := serve(srv.IntrospectHandler(), introspectRequest(rsAPIClientID, rsAPISecret, raw))
		require.Equal(t, http.StatusOK, rec.Code, raw)
		assert.JSONEq(t, inactiveBody, rec.Body.String(), raw)
	}

	assert.Zero(t, probe.calls.Load())
}

// TestIntrospectionPolicyDenialDisclosesNothing: a token the policy
// withholds answers exactly like an unknown token (RFC 7662 §2.2) — same
// status, headers and bytes — and the denial is not reported as an error.
func TestIntrospectionPolicyDenialDisclosesNothing(t *testing.T) {
	t.Parallel()

	probe := &policyProbe{allow: false}
	sink := &errorSink{}
	srv := newIntrospectServer(t, probe.decide, sink.hook)

	unknown := serve(srv.IntrospectHandler(), introspectRequest(rsAPIClientID, rsAPISecret, "ghost"))
	require.Equal(t, http.StatusOK, unknown.Code)
	assert.Equal(t, "application/json", unknown.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", unknown.Header().Get("Cache-Control"))

	for _, raw := range []string{"at-app", "rt-app"} {
		rec := serve(srv.IntrospectHandler(), introspectRequest(rsAPIClientID, rsAPISecret, raw))
		assertAnswersLikeUnknown(t, unknown, rec, raw)
	}

	assert.Equal(t, int32(2), probe.calls.Load(), "both tokens were withheld by the policy")
	assert.Empty(t, sink.codes(), "a denial is an expected outcome, not an incident")
}

// TestIntrospectionPolicyEnforcesBoundaries runs a tenant policy and a
// resource (audience) policy against two resource servers: each one sees
// what its boundary allows — refresh tokens included — and nothing else.
func TestIntrospectionPolicyEnforcesBoundaries(t *testing.T) {
	t.Parallel()

	// Tenant boundary: a caller sees the tokens of its own tenant's
	// clients.
	tenantOf := map[string]string{"app": "tenant-a", rsAPIClientID: "tenant-a", rsBillingClientID: "tenant-b"}
	tenantPolicy := func(_ context.Context, caller oauth2.Client, tok oauth2.IntrospectedToken) (bool, error) {
		tenant := tenantOf[caller.ID()]

		return tenant != "" && tenant == tenantOf[tok.ClientID], nil
	}

	// Resource boundary: a caller sees the access tokens issued for its own
	// audience, and refresh tokens never — they carry no audience.
	audienceOf := map[string]string{rsAPIClientID: "api", rsBillingClientID: "billing"}
	resourcePolicy := func(_ context.Context, caller oauth2.Client, tok oauth2.IntrospectedToken) (bool, error) {
		return tok.Kind == oauth2.TokenKindAccess && tok.Audience != "" && tok.Audience == audienceOf[caller.ID()], nil
	}

	cases := []struct {
		name       string
		policy     oauth2.IntrospectionPolicy
		callerID   string
		secret     string
		raw        string
		wantActive bool
	}{
		{"tenant: own tenant sees the access token", tenantPolicy, rsAPIClientID, rsAPISecret, "at-app", true},
		{"tenant: own tenant sees the refresh token", tenantPolicy, rsAPIClientID, rsAPISecret, "rt-app", true},
		{"tenant: other tenant denied the access token", tenantPolicy, rsBillingClientID, rsBillingSecret, "at-app", false},
		{"tenant: other tenant denied the refresh token", tenantPolicy, rsBillingClientID, rsBillingSecret, "rt-app", false},
		{"resource: audience sees the access token", resourcePolicy, rsAPIClientID, rsAPISecret, "at-app", true},
		{"resource: audience denied the refresh token", resourcePolicy, rsAPIClientID, rsAPISecret, "rt-app", false},
		{"resource: other resource denied the access token", resourcePolicy, rsBillingClientID, rsBillingSecret, "at-app", false},
		{"resource: other resource denied the refresh token", resourcePolicy, rsBillingClientID, rsBillingSecret, "rt-app", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := newIntrospectServer(t, tc.policy, nil)

			rec := serve(srv.IntrospectHandler(), introspectRequest(tc.callerID, tc.secret, tc.raw))
			require.Equal(t, http.StatusOK, rec.Code)

			if !tc.wantActive {
				assert.JSONEq(t, inactiveBody, rec.Body.String())

				return
			}

			body := decodeBody(t, rec)
			assert.Equal(t, true, body["active"])
			assert.Equal(t, "app", body["client_id"])
			assert.Equal(t, "alice", body["sub"])
		})
	}
}

// TestIntrospectionPolicyErrorFailsClosed: a policy that cannot decide
// withholds the token, whatever its bool says, and the failure reaches the
// error hook — the only place it can be seen.
func TestIntrospectionPolicyErrorFailsClosed(t *testing.T) {
	t.Parallel()

	errDirDown := errors.New("tenant directory down")
	probe := &policyProbe{allow: true, err: errDirDown}
	sink := &errorSink{}
	srv := newIntrospectServer(t, probe.decide, sink.hook)

	// An unknown token never reaches the policy, so it reports nothing.
	unknown := serve(srv.IntrospectHandler(), introspectRequest(rsAPIClientID, rsAPISecret, "ghost"))
	require.Equal(t, http.StatusOK, unknown.Code)

	// A 500 would tell the caller the token is active: answer exactly like
	// an unknown token instead.
	for _, raw := range []string{"at-app", "rt-app"} {
		rec := serve(srv.IntrospectHandler(), introspectRequest(rsAPIClientID, rsAPISecret, raw))
		assertAnswersLikeUnknown(t, unknown, rec, raw)
	}

	// Each failure reaches the hook, cause intact.
	got := sink.collected()
	require.Len(t, got, 2)

	for _, err := range got {
		assert.Equal(t, oauth2.CodeServerError, oauth2.IsCode(err))
		assert.ErrorContains(t, err, "introspection policy failed")
		assert.ErrorIs(t, err, errDirDown)
	}
}

// issuedTokens is the part of an RFC 6749 §5.1 body the flow test needs.
type issuedTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// decodeTokens decodes a successful /token response carrying both tokens.
func decodeTokens(t *testing.T, rec *httptest.ResponseRecorder) issuedTokens {
	t.Helper()

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var got issuedTokens
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.NotEmpty(t, got.AccessToken)
	require.NotEmpty(t, got.RefreshToken)

	return got
}

// TestPublicClientAuthorizationCodeFlowUnaffected: refusing public clients
// at /introspect leaves their own flow intact — authorization_code + PKCE,
// refresh and revocation, all with "none" — while a resource server still
// introspects their tokens.
func TestPublicClientAuthorizationCodeFlowUnaffected(t *testing.T) {
	t.Parallel()

	srv := newIntrospectServer(t, nil, nil)

	// asSPA builds a form POST authenticated with "none": client_id only.
	asSPA := func(path string, form url.Values) *http.Request {
		form.Set("client_id", spaClientID)

		return formRequest(path, form, false)
	}

	// /authorize (S256 PKCE) mints a code for the SPA...
	q := authorizeQuery()
	q.Set("client_id", spaClientID)

	rec := runAuthorize(srv, q, approve)
	require.Equal(t, http.StatusFound, rec.Code)

	code := mustLocation(t, rec).Query().Get("code")
	require.NotEmpty(t, code)

	// ...which /token exchanges with "none" and the PKCE verifier.
	issued := decodeTokens(t, serve(srv.TokenHandler(), asSPA("/oauth2/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {pkceVerifier},
	})))

	// The refresh token rotates with "none" too.
	refreshed := decodeTokens(t, serve(srv.TokenHandler(), asSPA("/oauth2/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {issued.RefreshToken},
	})))

	// The SPA itself cannot introspect its token...
	rec = serve(srv.IntrospectHandler(), asSPA("/oauth2/introspect", url.Values{"token": {refreshed.AccessToken}}))
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, oauth2.CodeInvalidClient, decodeError(t, rec))

	// ...but a confidential resource server can.
	rec = serve(srv.IntrospectHandler(), introspectRequest(rsAPIClientID, rsAPISecret, refreshed.AccessToken))
	require.Equal(t, http.StatusOK, rec.Code)

	body := decodeBody(t, rec)
	assert.Equal(t, true, body["active"])
	assert.Equal(t, spaClientID, body["client_id"])
	assert.Equal(t, "alice", body["sub"])
	assert.Equal(t, "api", body["aud"])

	// Revoking the refresh token with "none" still works, and takes the
	// family's access token down with it.
	rec = serve(srv.RevokeHandler(), asSPA("/oauth2/revoke", url.Values{"token": {refreshed.RefreshToken}}))
	require.Equal(t, http.StatusOK, rec.Code)

	rec = serve(srv.IntrospectHandler(), introspectRequest(rsAPIClientID, rsAPISecret, refreshed.AccessToken))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, inactiveBody, rec.Body.String())
}
