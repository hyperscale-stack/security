// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcrp_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	"github.com/hyperscale-stack/security/oidc/client/storage/memory"
	"github.com/hyperscale-stack/security/outbound"
	"github.com/stretchr/testify/require"
)

// corpusCaptured is when testdata/metadata was captured from the providers
// (then pretty-printed, members unchanged). Recapture with the opt-in
// TestLiveDiscovery when it reports a drift.
const corpusCaptured = "2026-10-12T08:24Z"

// clientProfile is one way an application configures a connection.
type clientProfile struct {
	name   string
	method oidcclient.AuthMethod
	mode   oidcclient.ResponseMode
}

var clientProfiles = []clientProfile{
	{"client_secret_basic", oidcclient.AuthMethodClientSecretBasic, oidcclient.ResponseModeQuery},
	{"client_secret_post", oidcclient.AuthMethodClientSecretPost, oidcclient.ResponseModeQuery},
	{"public client", oidcclient.AuthMethodNone, oidcclient.ResponseModeQuery},
	{"form_post", oidcclient.AuthMethodClientSecretPost, oidcclient.ResponseModeFormPost},
}

// corpusEntry is the discovery document of a real provider and the
// profiles New refuses for it (ErrInvalidMetadata), with the reason.
type corpusEntry struct {
	file    string // testdata/metadata/<file>.json
	source  string // the URL it was captured from
	refused map[string]string
}

// The public client is refused wherever token_endpoint_auth_methods_supported
// does not list "none" (or code_challenge_methods_supported lacks S256): New
// refuses a capability the provider says it lacks.
var metadataCorpus = []corpusEntry{
	{"google", "https://accounts.google.com/.well-known/openid-configuration", map[string]string{
		"public client": `"none" not in token_endpoint_auth_methods_supported`,
	}},
	{"microsoft-consumers", "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0/.well-known/openid-configuration", map[string]string{
		"public client": `"none" not in token_endpoint_auth_methods_supported, no code_challenge_methods_supported`,
	}},
	{"apple", "https://appleid.apple.com/.well-known/openid-configuration", map[string]string{
		"client_secret_basic": "token_endpoint_auth_methods_supported lists client_secret_post only",
		"public client":       `"none" not in token_endpoint_auth_methods_supported, no code_challenge_methods_supported`,
	}},
	{"gitlab", "https://gitlab.com/.well-known/openid-configuration", map[string]string{
		"public client": `"none" not in token_endpoint_auth_methods_supported`,
	}},
	{"salesforce", "https://login.salesforce.com/.well-known/openid-configuration", map[string]string{
		"public client": `"none" not in token_endpoint_auth_methods_supported`,
	}},
	{"auth0-samples", "https://samples.auth0.com/.well-known/openid-configuration", map[string]string{}},
}

// loadCorpusDocument reads a captured discovery document.
func loadCorpusDocument(t *testing.T, file string) map[string]any {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("testdata", "metadata", file+".json"))
	require.NoError(t, err)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))

	return doc
}

// rehost rewrites every absolute https URL of v to origin, keeping its path
// and query: every endpoint of the document then points at the test server.
func rehost(v any, origin string) any {
	switch x := v.(type) {
	case string:
		u, err := url.Parse(x)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return x
		}

		o, _ := url.Parse(origin)
		u.Scheme, u.Host = o.Scheme, o.Host

		return u.String()
	case []any:
		for i := range x {
			x[i] = rehost(x[i], origin)
		}
	case map[string]any:
		for k := range x {
			x[k] = rehost(x[k], origin)
		}
	}

	return v
}

// serveCorpusDocument serves doc, re-hosted, at its issuer's discovery URL
// (OpenID Connect Discovery 1.0 §4) on a TLS test server, and returns the
// re-hosted issuer and a trust pool.
func serveCorpusDocument(t *testing.T, doc map[string]any) (string, *x509.CertPool) {
	t.Helper()

	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	rehosted, ok := rehost(doc, srv.URL).(map[string]any)
	require.True(t, ok)

	issuer, ok := rehosted["issuer"].(string)
	require.True(t, ok)

	u, err := url.Parse(issuer)
	require.NoError(t, err)

	body, err := json.Marshal(rehosted)
	require.NoError(t, err)

	discovery := strings.TrimSuffix(u.Path, "/") + "/.well-known/openid-configuration"
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != discovery {
			http.NotFound(w, r)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	return issuer, pool
}

// corpusConfig is the Config of profile p for issuer.
func corpusConfig(issuer string, p clientProfile, policy outbound.Policy) oidcclient.Config {
	cfg := oidcclient.Config{
		ConnectionID:    "corpus",
		Issuer:          issuer,
		ClientID:        "rp",
		ClientSecret:    oidcclient.NewSecret("rp-secret"),
		AuthMethod:      p.method,
		RedirectURL:     "https://rp.example.com/oidc/corpus/callback",
		ResponseMode:    p.mode,
		Store:           memory.New(),
		TransactionKeys: []oidcclient.Secret{oidcclient.NewSecret(string(transactionKey))},
		Outbound:        policy,
	}

	if p.method == oidcclient.AuthMethodNone {
		cfg.ClientSecret = oidcclient.Secret{}
	}

	return cfg
}

// TestProviderMetadataCorpus runs the client's discovery and capability
// checks on the discovery documents of six real providers, pinned in
// testdata/metadata: each document is served as captured, re-hosted on a
// local TLS server, and every client profile is accepted or refused as the
// provider's metadata dictates — a regression corpus for metadata parsing
// and a record of the real-world caveats (public clients, Apple's
// client_secret_post).
func TestProviderMetadataCorpus(t *testing.T) {
	t.Parallel()

	for _, entry := range metadataCorpus {
		t.Run(entry.file, func(t *testing.T) {
			t.Parallel()

			issuer, pool := serveCorpusDocument(t, loadCorpusDocument(t, entry.file))
			policy := outbound.Policy{AllowedPrefixes: outbound.LoopbackPrefixes(), RootCAs: pool}

			for _, p := range clientProfiles {
				t.Run(p.name, func(t *testing.T) {
					_, err := oidcclient.New(t.Context(), corpusConfig(issuer, p, policy))
					if why, refused := entry.refused[p.name]; refused {
						require.ErrorIs(t, err, oidcclient.ErrInvalidMetadata, why)

						return
					}

					require.NoError(t, err)
				})
			}
		})
	}
}

// TestLiveDiscovery runs the same profiles against the live providers,
// through the default — strict — outbound policy. Opt in with
// OIDC_LIVE_DISCOVERY=1: it needs the Internet and no credentials. A
// failure is a drift between a provider and the corpus captured at
// corpusCaptured: recapture testdata/metadata and review the outcomes.
func TestLiveDiscovery(t *testing.T) {
	if os.Getenv("OIDC_LIVE_DISCOVERY") != "1" {
		t.Skip("set OIDC_LIVE_DISCOVERY=1 to run the live discovery checks (needs the Internet)")
	}

	t.Parallel()

	for _, entry := range metadataCorpus {
		t.Run(entry.file, func(t *testing.T) {
			t.Parallel()

			issuer, ok := loadCorpusDocument(t, entry.file)["issuer"].(string)
			require.True(t, ok)

			for _, p := range clientProfiles {
				t.Run(p.name, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
					defer cancel()

					_, err := oidcclient.New(ctx, corpusConfig(issuer, p, outbound.Policy{}))
					if why, refused := entry.refused[p.name]; refused {
						require.ErrorIs(t, err, oidcclient.ErrInvalidMetadata, "drift since %s: %s", corpusCaptured, why)

						return
					}

					require.NoError(t, err, "drift since %s from %s", corpusCaptured, entry.source)
				})
			}
		})
	}
}
