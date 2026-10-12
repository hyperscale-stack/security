// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package conformance_test

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	clientmemory "github.com/hyperscale-stack/security/oidc/client/storage/memory"
	"github.com/hyperscale-stack/security/outbound"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The RP driver is configured by run.sh through the environment.
const (
	envRP       = "OIDC_CONFORMANCE_RP"      // "1" runs the RP plans
	envSuiteURL = "CONFORMANCE_SERVER"       // the suite, https://localhost.emobix.co.uk:8443/
	envCA       = "OIDC_CONFORMANCE_CA"      // the run's CA, which signed the suite's certificate
	envRPOut    = "OIDC_CONFORMANCE_RP_OUT"  // where results and plan exports go
	envRPOnly   = "OIDC_CONFORMANCE_RP_ONLY" // optional: comma-separated plan keys to run
)

// rpRedirectURI is the redirect URI registered at the suite for our client.
// Nothing listens there: the driver reads the authorization responses
// itself.
const rpRedirectURI = "https://rp.conformance.test/oidc/conformance/callback"

// rpPlan is a plan run with our client.
type rpPlan struct {
	name    string
	variant map[string]string
	method  oidcclient.AuthMethod
	mode    oidcclient.ResponseMode
	// only, when set, limits the plan to these modules.
	only []string
	// key distinguishes plans run more than once with other variants.
	key string
}

var rpPlans = []rpPlan{
	{
		name: "oidcc-client-basic-certification-test-plan", key: "basic",
		variant: map[string]string{"client_registration": "static_client", "request_type": "plain_http_request"},
		method:  oidcclient.AuthMethodClientSecretBasic, mode: oidcclient.ResponseModeQuery,
	},
	{
		name: "oidcc-client-formpost-basic-certification-test-plan", key: "formpost-basic",
		variant: map[string]string{"client_registration": "static_client", "request_type": "plain_http_request"},
		method:  oidcclient.AuthMethodClientSecretBasic, mode: oidcclient.ResponseModeFormPost,
	},
	{
		name: "oidcc-client-config-certification-test-plan", key: "config",
		variant: map[string]string{
			"client_registration": "static_client", "request_type": "plain_http_request",
			"client_auth_type": "client_secret_basic", "response_mode": "default",
		},
		method: oidcclient.AuthMethodClientSecretBasic, mode: oidcclient.ResponseModeQuery,
	},
	{
		name: "oidcc-client-test-plan", key: "comprehensive",
		variant: map[string]string{
			"client_auth_type": "client_secret_basic", "response_type": "code", "response_mode": "default",
			"request_type": "plain_http_request", "client_registration": "static_client",
		},
		method: oidcclient.AuthMethodClientSecretBasic, mode: oidcclient.ResponseModeQuery,
	},
	{
		name: "oidcc-client-test-plan", key: "comprehensive-post", only: []string{"oidcc-client-test"},
		variant: map[string]string{
			"client_auth_type": "client_secret_post", "response_type": "code", "response_mode": "default",
			"request_type": "plain_http_request", "client_registration": "static_client",
		},
		method: oidcclient.AuthMethodClientSecretPost, mode: oidcclient.ResponseModeQuery,
	},
	{
		name: "oidcc-client-test-plan", key: "comprehensive-none", only: []string{"oidcc-client-test"},
		variant: map[string]string{
			"client_auth_type": "none", "response_type": "code", "response_mode": "default",
			"request_type": "plain_http_request", "client_registration": "static_client",
		},
		method: oidcclient.AuthMethodNone, mode: oidcclient.ResponseModeQuery,
	},
}

// moduleRun is the record of one module: the suite's verdict — its
// result, or its status when it has none (INTERRUPTED) — and ours, with
// the error text for the record.
type moduleRun struct {
	Plan    string `json:"plan"`
	Module  string `json:"module"`
	ID      string `json:"id"`
	Result  string `json:"result"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail,omitempty"`
}

// expectation is what testdata/rp-expected.json pins for a module.
type expectation struct {
	Result    string `json:"result"`
	Outcome   string `json:"outcome"`
	Rationale string `json:"rationale,omitempty"`
}

// TestConformanceRPPlans runs our relying party through the suite's RP
// plans. For every module it creates the test, logs in with oidc/client
// against the module's issuer — discovery, authorization request,
// callback, UserInfo on success — and records the suite's result and our
// outcome (the client's error sentinel, or "ok"). Both are compared with
// testdata/rp-expected.json: any difference fails, positive controls
// included. It runs only with OIDC_CONFORMANCE_RP=1 (run.sh).
func TestConformanceRPPlans(t *testing.T) {
	if os.Getenv(envRP) != "1" {
		t.Skip("opt-in: internal/interop/oidcstack/conformance/run.sh sets " + envRP)
	}

	ctx := t.Context()
	api := newSuiteAPI(t, os.Getenv(envSuiteURL), os.Getenv(envCA))
	out := os.Getenv(envRPOut)
	require.NoError(t, os.MkdirAll(out, 0o750))

	identity, err := api.server(ctx)
	require.NoError(t, err)
	writeJSON(t, filepath.Join(out, "suite-server.json"), identity)

	// At least 256 bits: the suite signs with it in the HS256 module.
	secret := rand.Text() + rand.Text()
	config := rpConfig(t, secret)

	var runs []moduleRun

	only := strings.Split(os.Getenv(envRPOnly), ",")

	for _, plan := range rpPlans {
		if only[0] != "" && !slices.Contains(only, plan.key) {
			continue
		}

		planID, modules, err := api.createPlan(ctx, plan.name, plan.variant, config)
		require.NoError(t, err, plan.key)

		for _, m := range modules {
			if len(plan.only) > 0 && !slices.Contains(plan.only, m.TestModule) {
				continue
			}

			run := runModule(t, api, plan, planID, m, secret)
			t.Logf("%-20s %-58s %-11s %s", plan.key, m.TestModule, run.Result, run.Outcome)
			runs = append(runs, run)
		}

		if err := api.exportHTML(ctx, planID, filepath.Join(out, plan.key+".zip")); err != nil {
			t.Logf("export %s: %v", plan.key, err)
		}
	}

	writeJSON(t, filepath.Join(out, "results.json"), runs)
	if only[0] == "" {
		compareWithExpectations(t, runs)
	}
}

// rpConfig is the plans' configuration: our client, statically registered.
func rpConfig(t *testing.T, secret string) []byte {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("testdata", "rp-config.json"))
	require.NoError(t, err)

	var config map[string]any
	require.NoError(t, json.Unmarshal(raw, &config))

	client, ok := config["client"].(map[string]any)
	require.True(t, ok, "rp-config.json has a client")

	client["client_secret"] = secret
	client["redirect_uri"] = rpRedirectURI

	out, err := json.Marshal(config)
	require.NoError(t, err)

	return out
}

// runModule runs one module with our client and returns its record.
func runModule(t *testing.T, api *suiteAPI, plan rpPlan, planID string, m planModule, secret string) moduleRun {
	t.Helper()

	ctx := t.Context()
	run := moduleRun{Plan: plan.key, Module: m.TestModule}

	id, err := api.createModule(ctx, planID, m)
	require.NoError(t, err, m.TestModule)

	run.ID = id

	state, err := api.waitState(ctx, id, time.Minute, "CONFIGURED", "WAITING", "FINISHED")
	require.NoError(t, err, m.TestModule)

	if state == "CONFIGURED" {
		state, err = api.waitState(ctx, id, time.Minute, "WAITING", "FINISHED")
		require.NoError(t, err, m.TestModule)
	}

	if state == "WAITING" {
		exposed, err := api.exposed(ctx, id)
		require.NoError(t, err, m.TestModule)

		run.Outcome, run.Detail = loginWith(t, plan, m.TestModule, exposed["issuer"], secret)
	} else {
		run.Outcome = "not-run"
	}

	// Positive modules finish on the UserInfo request, negative ones after
	// their 5 s wait for one; a module waiting for something our client
	// never does (WebFinger, registration…) is stopped: INTERRUPTED.
	if _, err := api.waitState(ctx, id, 30*time.Second, "FINISHED"); err != nil {
		require.NoError(t, api.stop(ctx, id), m.TestModule)

		_, err = api.waitState(ctx, id, time.Minute, "FINISHED")
		require.NoError(t, err, m.TestModule)
	}

	info, err := api.info(ctx, id)
	require.NoError(t, err, m.TestModule)

	run.Result = info.Result
	if run.Result == "" {
		run.Result = info.Status
	}

	return run
}

// clock is the client's clock: the wall clock plus an offset the driver
// moves past the client's minimum key-set refresh interval between the
// logins of a key-rotation module.
type clock struct{ offset atomic.Int64 }

func (c *clock) now() time.Time { return time.Now().Add(time.Duration(c.offset.Load())) }

// loginWith logs in with our client against the module's issuer — twice
// for the key-rotation modules — and returns "ok" or the client's error,
// with its text.
func loginWith(t *testing.T, plan rpPlan, module, issuer, secret string) (string, string) {
	t.Helper()

	ctx := t.Context()
	pool := caPool(t, os.Getenv(envCA))
	clk := &clock{}

	key := make([]byte, oidcclient.MinTransactionKeySize)
	_, _ = rand.Read(key)

	cfg := oidcclient.Config{
		ConnectionID: "conformance", Issuer: issuer, ClientID: "hyperscale-rp", AuthMethod: plan.method,
		RedirectURL: rpRedirectURI, Scopes: []string{"profile", "email", "address", "phone"},
		ResponseMode: plan.mode, Store: clientmemory.New(), TransactionKeys: [][]byte{key},
		Outbound: outbound.Policy{RootCAs: pool, AllowedPrefixes: outbound.LoopbackPrefixes()},
		Now:      clk.now,
	}

	if plan.method != oidcclient.AuthMethodNone {
		cfg.ClientSecret = secret
	}

	client, err := oidcclient.New(ctx, cfg)
	if err != nil {
		return outcomeOf(err), err.Error()
	}

	// The discovery module finishes once the configuration was fetched, and
	// fails any request that follows.
	if module == "oidcc-client-test-discovery-openid-config" {
		return "ok", ""
	}

	logins := 1
	if strings.Contains(module, "signing-key-rotation") && !strings.HasSuffix(module, "just-before-signing") {
		logins = 2
	}

	for i := range logins {
		if i > 0 {
			// Past the client's 10 s minimum interval between key-set
			// refreshes (review F6).
			clk.offset.Add(int64(11 * time.Second))
		}

		if err := loginOnce(t, client, module); err != nil {
			return outcomeOf(err), err.Error()
		}
	}

	return "ok", ""
}

// loginOnce runs one login and the UserInfo request that completes it.
func loginOnce(t *testing.T, client *oidcclient.Client, module string) error {
	t.Helper()

	ctx := t.Context()

	opts := oidcclient.AuthOptions{}

	if module == "oidcc-client-test-form-post-error" {
		zero := time.Duration(0)
		opts = oidcclient.AuthOptions{MaxAge: &zero, Prompt: []string{"none"}}
	}

	ar, err := client.Begin(ctx, opts)
	if err != nil {
		return err //nolint:wrapcheck // the client's own sentinel
	}

	cb, err := authorizationResponse(t, ar)
	if err != nil {
		return err
	}

	id, err := client.Complete(ctx, cb)
	if err != nil {
		return err //nolint:wrapcheck // the client's own sentinel
	}

	// The jwks_uri module finishes once the configuration and the JWK Set —
	// fetched to verify the ID Token — were requested, and fails any
	// request that follows.
	if module == "oidcc-client-test-discovery-jwks-uri-keys" {
		return nil
	}

	_, err = client.UserInfo(ctx, id)

	return err //nolint:wrapcheck // the client's own sentinel
}

// browser is the user agent of the driver: it trusts the run's CA and
// reads the authorization response instead of following it.
func browser(t *testing.T) *http.Client {
	t.Helper()

	return newSuiteAPI(t, os.Getenv(envSuiteURL), os.Getenv(envCA)).http
}

var (
	formAction = regexp.MustCompile(`<form[^>]*action="([^"]*)"`)
	formInput  = regexp.MustCompile(`<input[^>]*name="([^"]*)"[^>]*value="([^"]*)"`)
)

// errNoResponse reports an authorization endpoint answer that is neither a
// redirect nor a form_post page.
var errNoResponse = errors.New("no authorization response")

// authorizationResponse sends the authorization request as a user agent
// would and returns the response delivered to the redirect URI: the query
// of a redirect, or the fields of a form_post page (OAuth 2.0 Form Post
// Response Mode §2).
func authorizationResponse(t *testing.T, ar *oidcclient.AuthRequest) (oidcclient.Callback, error) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ar.URL, nil)
	if err != nil {
		return oidcclient.Callback{}, fmt.Errorf("request: %w", err)
	}

	resp, err := browser(t).Do(req)
	if err != nil {
		return oidcclient.Callback{}, fmt.Errorf("authorization endpoint: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return oidcclient.Callback{}, fmt.Errorf("authorization endpoint: %w", err)
	}

	if loc := resp.Header.Get("Location"); loc != "" {
		u, err := url.Parse(loc)
		if err != nil {
			return oidcclient.Callback{}, fmt.Errorf("location: %w", err)
		}

		return oidcclient.Callback{Mode: oidcclient.ResponseModeQuery, URL: u, Params: u.Query(), Binding: ar.Binding}, nil
	}

	action := formAction.FindSubmatch(body)
	if action == nil {
		return oidcclient.Callback{}, fmt.Errorf("%w: HTTP %d", errNoResponse, resp.StatusCode)
	}

	u, err := url.Parse(html.UnescapeString(string(action[1])))
	if err != nil {
		return oidcclient.Callback{}, fmt.Errorf("form action: %w", err)
	}

	params := url.Values{}
	for _, field := range formInput.FindAllSubmatch(body, -1) {
		params.Add(html.UnescapeString(string(field[1])), html.UnescapeString(string(field[2])))
	}

	return oidcclient.Callback{Mode: oidcclient.ResponseModeFormPost, URL: u, Params: params, Binding: ar.Binding}, nil
}

// sentinels are the client's errors, the most specific first: an outcome
// names the first the error matches.
var sentinels = []struct {
	name string
	err  error
}{
	{"ErrIDTokenIssuer", oidcclient.ErrIDTokenIssuer},
	{"ErrIDTokenAudience", oidcclient.ErrIDTokenAudience},
	{"ErrIDTokenAuthorizedParty", oidcclient.ErrIDTokenAuthorizedParty},
	{"ErrIDTokenExpired", oidcclient.ErrIDTokenExpired},
	{"ErrIDTokenIssuedAt", oidcclient.ErrIDTokenIssuedAt},
	{"ErrIDTokenNotYetValid", oidcclient.ErrIDTokenNotYetValid},
	{"ErrIDTokenNonce", oidcclient.ErrIDTokenNonce},
	{"ErrIDTokenMissingClaim", oidcclient.ErrIDTokenMissingClaim},
	{"ErrIDTokenAuthTime", oidcclient.ErrIDTokenAuthTime},
	{"ErrIDTokenACR", oidcclient.ErrIDTokenACR},
	{"ErrIDTokenAlgorithm", oidcclient.ErrIDTokenAlgorithm},
	{"ErrIDTokenType", oidcclient.ErrIDTokenType},
	{"ErrIDTokenSignature", oidcclient.ErrIDTokenSignature},
	{"ErrUnknownSigningKey", oidcclient.ErrUnknownSigningKey},
	{"ErrIDTokenMalformed", oidcclient.ErrIDTokenMalformed},
	{"ErrAccessTokenHash", oidcclient.ErrAccessTokenHash},
	{"ErrKeySet", oidcclient.ErrKeySet},
	{"ErrInvalidIDToken", oidcclient.ErrInvalidIDToken},
	{"ErrUserInfoSubject", oidcclient.ErrUserInfoSubject},
	{"ErrUserInfoUnsupported", oidcclient.ErrUserInfoUnsupported},
	{"ErrUserInfo", oidcclient.ErrUserInfo},
	{"ErrInvalidTokenResponse", oidcclient.ErrInvalidTokenResponse},
	{"ErrTokenEndpoint", oidcclient.ErrTokenEndpoint},
	{"ErrIssuerParameter", oidcclient.ErrIssuerParameter},
	{"ErrAuthorizationFailed", oidcclient.ErrAuthorizationFailed},
	{"ErrInvalidCallback", oidcclient.ErrInvalidCallback},
	{"ErrTransactionMismatch", oidcclient.ErrTransactionMismatch},
	{"ErrIssuerMismatch", oidcclient.ErrIssuerMismatch},
	{"ErrInvalidMetadata", oidcclient.ErrInvalidMetadata},
	{"ErrDiscovery", oidcclient.ErrDiscovery},
	{"ErrInvalidConfig", oidcclient.ErrInvalidConfig},
}

// outcomeOf names err by its most specific sentinel — with the error code
// of an authorization error.
func outcomeOf(err error) string {
	var authErr *oidcclient.AuthorizationError
	if errors.As(err, &authErr) {
		return "ErrAuthorizationFailed(" + authErr.Code + ")"
	}

	for _, s := range sentinels {
		if errors.Is(err, s.err) {
			return s.name
		}
	}

	if errors.Is(err, errNoResponse) {
		return "no authorization response"
	}

	return "unclassified"
}

// compareWithExpectations fails on any module whose suite result or our
// outcome differs from testdata/rp-expected.json, on any unexpected module
// and on any expected module that did not run.
func compareWithExpectations(t *testing.T, runs []moduleRun) {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("testdata", "rp-expected.json"))
	require.NoError(t, err)

	var expected map[string]map[string]expectation
	require.NoError(t, json.Unmarshal(raw, &expected))

	seen := map[string]bool{}

	for _, run := range runs {
		key := run.Plan + "/" + run.Module
		seen[key] = true

		want, ok := expected[run.Plan][run.Module]
		if !assert.True(t, ok, "%s ran (%s, %s) but has no expectation", key, run.Result, run.Outcome) {
			continue
		}

		assert.Equal(t, want.Result, run.Result, "%s: suite result", key)
		assert.Equal(t, want.Outcome, run.Outcome, "%s: our outcome", key)
	}

	var missing []string

	for plan, modules := range expected {
		for module := range modules {
			if !seen[plan+"/"+module] {
				missing = append(missing, plan+"/"+module)
			}
		}
	}

	sort.Strings(missing)
	assert.Empty(t, missing, "expected modules that did not run")
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()

	raw, err := json.MarshalIndent(v, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, raw, 0o600))
}
