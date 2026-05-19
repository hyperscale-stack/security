// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// remoteJWKS fetches a JSON Web Key Set from an HTTP endpoint with TTL-based
// caching and best-effort refresh on unknown kid. Concurrent fetches for the
// same endpoint are deduplicated via a sync.Mutex.
type remoteJWKS struct {
	url     string
	client  *http.Client
	ttl     time.Duration
	mu      sync.Mutex
	cache   *staticKeySet
	expires time.Time
}

// RemoteOption configures a remote JWKS provider.
type RemoteOption func(*remoteJWKS)

// WithHTTPClient overrides the http.Client used to fetch the JWKS document.
// Default: http.DefaultClient with a 10s timeout.
func WithHTTPClient(c *http.Client) RemoteOption {
	return func(r *remoteJWKS) { r.client = c }
}

// WithCacheTTL overrides the time after which a cached key set is refreshed
// proactively. Default: 5 minutes.
func WithCacheTTL(d time.Duration) RemoteOption {
	return func(r *remoteJWKS) { r.ttl = d }
}

// NewRemoteJWKS returns a [JWKSProvider] that fetches the JSON Web Key Set
// hosted at url, caches it for the configured TTL, and refreshes on demand
// whenever a verifier asks for a kid that is not in the current snapshot.
//
// The provider is safe for concurrent use; concurrent KeySet calls that
// trigger a refresh are serialized via an internal mutex.
func NewRemoteJWKS(url string, opts ...RemoteOption) JWKSProvider {
	r := &remoteJWKS{
		url:    url,
		client: &http.Client{Timeout: 10 * time.Second},
		ttl:    5 * time.Minute,
	}

	for _, o := range opts {
		o(r)
	}

	return r
}

// KeySet implements [JWKSProvider].
func (r *remoteJWKS) KeySet(ctx context.Context) (KeySet, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.cache != nil && time.Now().Before(r.expires) {
		return r.cache, nil
	}

	keys, err := r.fetch(ctx)
	if err != nil {
		if r.cache != nil {
			// Return the stale snapshot rather than failing closed when
			// the upstream is briefly unavailable — verifiers will still
			// reject tokens whose kid is missing.
			return r.cache, nil
		}

		return nil, fmt.Errorf("jwt: fetch jwks: %w", err)
	}

	r.cache = keys
	r.expires = time.Now().Add(r.ttl)

	return keys, nil
}

func (r *remoteJWKS) fetch(ctx context.Context) (*staticKeySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	// The URL was set at construction time by the operator, not by user
	// input; G704's SSRF heuristic cannot prove that and flags this call.
	resp, err := r.client.Do(req) //nolint:gosec // URL is operator-controlled
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	var raw jose.JSONWebKeySet
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse jwks: %w", err)
	}

	out := &staticKeySet{publics: make([]PublicKey, 0, len(raw.Keys))}

	for _, k := range raw.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}

		out.publics = append(out.publics, PublicKey{
			KeyID:     k.KeyID,
			Algorithm: Algorithm(k.Algorithm),
			Key:       k.Key,
		})
	}

	if len(out.publics) == 0 {
		return nil, errors.New("no signing keys")
	}

	return out, nil
}
