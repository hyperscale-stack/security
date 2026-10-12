// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package conformance_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// suiteAPI is a client of the conformance suite's REST API, as
// scripts/conformance.py uses it, in development mode (no token).
type suiteAPI struct {
	base string // ends with a slash
	http *http.Client
}

// newSuiteAPI returns a client of the suite at base, trusting the CA in
// caFile — the run's CA, which signed the suite's nginx certificate.
func newSuiteAPI(t *testing.T, base, caFile string) *suiteAPI {
	t.Helper()

	pool := caPool(t, caFile)

	if !strings.HasSuffix(base, "/") {
		base += "/"
	}

	return &suiteAPI{base: base, http: &http.Client{
		Timeout:   2 * time.Minute,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		// The authorization responses are read, never followed.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// caPool reads a PEM certificate file into a pool.
func caPool(t *testing.T, caFile string) *x509.CertPool {
	t.Helper()

	pem, err := os.ReadFile(caFile) //nolint:gosec // G304: the run's CA, named by run.sh
	require.NoError(t, err)

	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(pem), "no certificate in %s", caFile)

	return pool
}

// call sends a request to the API and decodes the JSON answer into out.
func (s *suiteAPI) call(ctx context.Context, method, path string, query url.Values, body []byte, want int, out any) error {
	target := s.base + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := s.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}

	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}

	if resp.StatusCode != want {
		return fmt.Errorf("%s %s: HTTP %d: %.300s", method, path, resp.StatusCode, raw)
	}

	if out == nil {
		return nil
	}

	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}

	return nil
}

// planModule is a module of a created plan.
type planModule struct {
	TestModule string            `json:"testModule"`
	Variant    map[string]string `json:"variant"`
}

// createPlan creates the plan name with its variant and configuration.
func (s *suiteAPI) createPlan(ctx context.Context, name string, variant map[string]string, config []byte) (string, []planModule, error) {
	query := url.Values{"planName": {name}}

	if len(variant) > 0 {
		raw, err := json.Marshal(variant)
		if err != nil {
			return "", nil, fmt.Errorf("plan variant: %w", err)
		}

		query.Set("variant", string(raw))
	}

	var created struct {
		ID      string       `json:"id"`
		Modules []planModule `json:"modules"`
	}

	if err := s.call(ctx, http.MethodPost, "api/plan", query, config, http.StatusCreated, &created); err != nil {
		return "", nil, err
	}

	return created.ID, created.Modules, nil
}

// createModule creates an instance of module in plan.
func (s *suiteAPI) createModule(ctx context.Context, plan string, m planModule) (string, error) {
	query := url.Values{"test": {m.TestModule}, "plan": {plan}}

	if len(m.Variant) > 0 {
		raw, err := json.Marshal(m.Variant)
		if err != nil {
			return "", fmt.Errorf("module variant: %w", err)
		}

		query.Set("variant", string(raw))
	}

	var created struct {
		ID string `json:"id"`
	}

	if err := s.call(ctx, http.MethodPost, "api/runner", query, nil, http.StatusCreated, &created); err != nil {
		return "", err
	}

	return created.ID, nil
}

// errStateTimeout reports a module that did not reach a wanted state.
var errStateTimeout = errors.New("conformance: the module did not reach the state in time")

// waitState long-polls the module until its status is one of states, for
// at most timeout.
func (s *suiteAPI) waitState(ctx context.Context, id string, timeout time.Duration, states ...string) (string, error) {
	deadline := time.Now().Add(timeout)
	wanted := strings.Join(append(states, "INTERRUPTED"), ",")

	for time.Now().Before(deadline) {
		budget := min(time.Until(deadline), 30*time.Second)

		var answer struct {
			State   string `json:"state"`
			Timeout bool   `json:"timeout"`
		}

		query := url.Values{"states": {wanted}, "timeoutMs": {fmt.Sprint(budget.Milliseconds())}}
		if err := s.call(ctx, http.MethodGet, "api/runner/"+id+"/wait-state", query, nil, http.StatusOK, &answer); err != nil {
			return "", err
		}

		if !answer.Timeout && answer.State != "" {
			return answer.State, nil
		}
	}

	return "", errStateTimeout
}

// moduleInfo is what /api/info says about a module instance.
type moduleInfo struct {
	Status string `json:"status"`
	Result string `json:"result"`
}

func (s *suiteAPI) info(ctx context.Context, id string) (moduleInfo, error) {
	var info moduleInfo

	err := s.call(ctx, http.MethodGet, "api/info/"+id, nil, nil, http.StatusOK, &info)

	return info, err
}

// exposed returns the values a running module exposes — the issuer of an
// RP test's provider among them.
func (s *suiteAPI) exposed(ctx context.Context, id string) (map[string]string, error) {
	var runner struct {
		Exposed map[string]string `json:"exposed"`
	}

	err := s.call(ctx, http.MethodGet, "api/runner/"+id, nil, nil, http.StatusOK, &runner)

	return runner.Exposed, err
}

// stop interrupts a module instance that did not finish by itself.
func (s *suiteAPI) stop(ctx context.Context, id string) error {
	return s.call(ctx, http.MethodDelete, "api/runner/"+id, nil, nil, http.StatusOK, nil)
}

// server returns the suite's identity (version, revision, build time).
func (s *suiteAPI) server(ctx context.Context) (map[string]any, error) {
	var identity map[string]any

	err := s.call(ctx, http.MethodGet, "api/server", nil, nil, http.StatusOK, &identity)

	return identity, err
}

// exportHTML saves the plan's HTML export (a zip) at path.
func (s *suiteAPI) exportHTML(ctx context.Context, plan, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.base+"api/plan/exporthtml/"+plan, nil)
	if err != nil {
		return fmt.Errorf("export %s: %w", plan, err)
	}

	resp, err := s.http.Do(req)
	if err != nil {
		return fmt.Errorf("export %s: %w", plan, err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("export %s: HTTP %d", plan, resp.StatusCode)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("export %s: %w", plan, err)
	}

	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return fmt.Errorf("export %s: %w", plan, err)
	}

	return nil
}
