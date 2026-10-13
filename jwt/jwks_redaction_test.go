// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRemoteJWKSRedactsItsURL pins audit CORE-15: the provider prints,
// logs and encodes its URL without the query — an API key may sit there —
// nor the fragment.
func TestRemoteJWKSRedactsItsURL(t *testing.T) {
	t.Parallel()

	p, err := jwtsec.NewRemoteJWKS("https://idp.example/tenant/jwks?api_key=k3y-S3CR3T#frag")
	require.NoError(t, err)

	for way, rendered := range keyRenderings(t, p) {
		assert.NotContains(t, rendered, "k3y-S3CR3T", way)
		assert.NotContains(t, rendered, "api_key", way)
		assert.NotContains(t, rendered, "frag", way)
	}

	assert.Equal(t, `jwtsec.RemoteJWKS{URL: "https://idp.example/tenant/jwks?REDACTED"}`, fmt.Sprint(p))
	assert.Contains(t, fmt.Sprintf("%v", jwtsec.NewVerifier(p)), "Provider: *jwtsec.remoteJWKS")
}

// TestRemoteJWKSErrorsDoNotLeakTheURL pins review F3: net/http puts the
// request URL — user name and query included — in every transport error;
// the provider's errors and spans carry the redacted URL only. Not
// parallel: it installs the recording tracer provider.
func TestRemoteJWKSErrorsDoNotLeakTheURL(t *testing.T) {
	_, pub := ecKey(t, "k")
	e := newJWKSEndpoint(t, jwksJSON(t, sigKey(pub)))
	e.set(jwksJSON(t, sigKey(pub)), http.StatusInternalServerError)

	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[],"pad":"` + strings.Repeat("A", 1<<20) + `"}`))
	}))
	t.Cleanup(big.Close)

	// A redirect to another origin is refused: net/http names the target
	// URL, a secret in its query, in its error.
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, e.srv.URL+"/keys?token=S3CR3T-2", http.StatusFound)
	}))
	t.Cleanup(redirect.Close)

	const query = "?api_key=S3CR3T"

	providers := map[string]func() (jwtsec.JWKSProvider, error){
		"refused destination": func() (jwtsec.JWKSProvider, error) { return jwtsec.NewRemoteJWKS(e.srv.URL + "/jwks" + query) },
		"status 500": func() (jwtsec.JWKSProvider, error) {
			return jwtsec.NewRemoteJWKS(e.srv.URL+"/jwks"+query, e.policy())
		},
		"connection refused (opt-out client)": func() (jwtsec.JWKSProvider, error) {
			return jwtsec.NewRemoteJWKS("http://127.0.0.1:1/jwks"+query, jwtsec.WithHTTPClient(&http.Client{}))
		},
		"oversized body (opt-out client)": func() (jwtsec.JWKSProvider, error) {
			return jwtsec.NewRemoteJWKS(big.URL+"/jwks"+query, jwtsec.WithHTTPClient(&http.Client{}))
		},
		"redirect to a secret URL": func() (jwtsec.JWKSProvider, error) {
			return jwtsec.NewRemoteJWKS(redirect.URL+"/jwks"+query, jwtsec.WithHTTPClient(redirect.Client()))
		},
	}

	for name, build := range providers {
		p, err := build()
		require.NoError(t, err, name)

		var verifyErr error

		spans := record(func() {
			_, verifyErr = jwtsec.NewVerifier(p).Verify(context.Background(), tokenFor(t, mustKey(t), "k"), nil)
		})

		require.ErrorIs(t, verifyErr, jwtsec.ErrKeySetUnavailable, name)
		assert.Equal(t, 1, strings.Count(verifyErr.Error(), "/jwks?REDACTED"), "%s: the URL is named once: %v", name, verifyErr)

		rendered := []string{verifyErr.Error(), fmt.Sprintf("%+v", verifyErr), fmt.Sprintf("%#v", verifyErr)}

		for _, s := range spans {
			rendered = append(rendered, s.errs...)
			rendered = append(rendered, s.attr("jwt.jwks.url"))
		}

		for _, r := range rendered {
			assert.NotContains(t, r, "S3CR3T", name)
			assert.NotContains(t, r, "api_key", name)
		}

		require.NotEmpty(t, named(spans, "jwtsec.RemoteJWKS.Fetch"), name)
	}
}

// TestRemoteJWKSBoundsDocumentErrors pins review F1: a hostile JWK Set —
// a number literal of a megabyte — yields neither a megabyte error nor
// megabytes of allocations on every verification, nor a megabyte span
// event. Not parallel: it installs the recording tracer provider and
// measures the allocations of the process.
func TestRemoteJWKSBoundsDocumentErrors(t *testing.T) {
	huge := "1" + strings.Repeat("0", 1_000_000)
	tok := tokenFor(t, mustKey(t), "k")

	for name, doc := range map[string]string{
		"beside the keys": `{"keys":[],"x":` + huge + `}`,
		"as the keys":     `{"keys":` + huge + `}`,
		"as a key":        `{"keys":[` + huge + `]}`,
	} {
		e := newJWKSEndpoint(t, []byte(doc))
		v := jwtsec.NewVerifier(e.provider(t, newTestClock()))

		var verifyErr error

		spans := record(func() { _, verifyErr = v.Verify(context.Background(), tok, nil) })

		require.Error(t, verifyErr, name)
		assert.Less(t, len(verifyErr.Error()), 400, name)

		fetches := named(spans, "jwtsec.RemoteJWKS.Fetch")
		require.Len(t, fetches, 1, name)

		for _, recorded := range fetches[0].errs {
			assert.Less(t, len(recorded), 400, name)
		}

		const calls = 20

		var before, after runtime.MemStats

		runtime.ReadMemStats(&before)

		for range calls {
			_, _ = v.Verify(context.Background(), tok, nil)
		}

		runtime.ReadMemStats(&after)
		assert.Less(t, (after.TotalAlloc-before.TotalAlloc)/calls, uint64(64<<10), "%s: bytes allocated per verification", name)
	}
}

// mustKey returns a fresh ES256 signing key.
func mustKey(t *testing.T) jwtsec.PrivateKey {
	t.Helper()

	priv, _ := ecKey(t, "k")

	return priv
}

// TestRemoteJWKSFetchSpan pins the fetch span (docs/observability.md): a
// root span of its own — the fetch outlives the request that started it —
// linked to the caller's span, with the kept and ignored key counts. Not
// parallel: it installs the recording tracer provider.
func TestRemoteJWKSFetchSpan(t *testing.T) {
	priv, pub := ecKey(t, "k")
	doc := `{"keys":[` + jwkOf(t, sigKey(pub)) + `,{"kty":"XYZ","kid":"x"}]}`
	e := newJWKSEndpoint(t, []byte(doc))
	p := e.provider(t, newTestClock())

	spans := record(func() {
		_, err := jwtsec.NewVerifier(p).Verify(context.Background(), tokenFor(t, priv, "k"), nil)
		require.NoError(t, err)
	})

	fetches := named(spans, "jwtsec.RemoteJWKS.Fetch")
	require.Len(t, fetches, 1)

	f := fetches[0]
	assert.True(t, f.root, "a new root span")
	assert.Len(t, f.links, 1, "linked to the caller's span")
	assert.Equal(t, "1", f.attr("jwt.jwks.keys"))
	assert.Equal(t, "1", f.attr("jwt.jwks.ignored"))
	assert.Equal(t, e.srv.URL+"/jwks", f.attr("jwt.jwks.url"))
}

// TestRemoteJWKSLeavesNoGoroutineBehind pins that a caller giving up and
// a hung upstream leave no goroutine running once the fetch timed out.
// Not parallel: it counts the process's goroutines.
func TestRemoteJWKSLeavesNoGoroutineBehind(t *testing.T) {
	runtime.GC()

	baseline := runtime.NumGoroutine()

	func() {
		_, pub := ecKey(t, "k")
		e := &jwksEndpoint{doc: jwksJSON(t, sigKey(pub)), status: http.StatusOK}
		e.srv = httptest.NewTLSServer(http.HandlerFunc(e.serve))
		release := e.hold()

		p, err := jwtsec.NewRemoteJWKS(e.srv.URL+"/jwks", e.policy())
		require.NoError(t, err)

		jwtsec.SetRemoteJWKSFetchTimeout(p, 100*time.Millisecond)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		_, err = p.KeySet(ctx)
		require.ErrorIs(t, err, jwtsec.ErrKeySetUnavailable)

		waitIdle(t, p) // the fetch timed out
		release()
		e.srv.Close()
	}()

	// Polled on this goroutine: require.Eventually runs its condition on
	// a goroutine of its own, which the count would include.
	for deadline := time.Now().Add(10 * time.Second); runtime.NumGoroutine() > baseline && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}

	if n := runtime.NumGoroutine(); n > baseline {
		buf := make([]byte, 1<<20)
		t.Fatalf("goroutines left behind: %d > %d\n%s", n, baseline, buf[:runtime.Stack(buf, true)])
	}
}
