// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/hyperscale-stack/security/outbound"
)

// Client is the Relying Party of one connection. It is safe for concurrent
// use; the application builds one per connection and keeps it.
type Client struct {
	cfg          Config
	callbackPath string
	md           *providerMetadata
	authURL      *url.URL
	algs         []Algorithm
	joseAlgs     []jose.SignatureAlgorithm
	keys         *keySet      // fetches with the configured redirect policy
	send         *http.Client // token and UserInfo: credentials, never redirected
	now          func() time.Time
}

// refuseRedirect is the CheckRedirect of credential-bearing requests.
func refuseRedirect(*http.Request, []*http.Request) error {
	return fmt.Errorf("%w: a token or UserInfo request is never redirected", outbound.ErrRedirectNotAllowed)
}

// New validates cfg, retrieves the provider metadata from
// cfg.Issuer + "/.well-known/openid-configuration" — the issuer is never
// taken from anywhere else — and returns the Client of the connection.
//
// It fails with ErrInvalidConfig before any network access when cfg is
// refused, ErrDiscovery when the metadata cannot be retrieved,
// ErrIssuerMismatch when its issuer is not byte-for-byte cfg.Issuer (OpenID
// Connect Discovery 1.0 §4.3), and ErrInvalidMetadata when it is malformed,
// misses a REQUIRED member, names a non-https endpoint, or lacks a
// capability cfg needs (code flow, response mode, client authentication
// method, an ID Token algorithm in common, PKCE S256 for a public client).
// The keys are fetched on first use. To pick up changed metadata, build a
// new Client.
func New(ctx context.Context, cfg Config) (*Client, error) {
	cfg, redirect, err := cfg.normalized()
	if err != nil {
		return nil, err
	}

	fetch, err := outbound.NewClient(cfg.Outbound)
	if err != nil {
		return nil, fmt.Errorf("%w: Outbound: %w", ErrInvalidConfig, err)
	}

	// Token and UserInfo requests carry credentials: they share the
	// policy but never follow a redirect.
	send := *fetch
	send.CheckRedirect = refuseRedirect

	md, err := discover(ctx, fetch, cfg.Issuer, cfg.Outbound.AllowHTTP)
	if err != nil {
		return nil, err
	}

	algs, err := md.negotiate(cfg)
	if err != nil {
		return nil, err
	}

	joseAlgs := make([]jose.SignatureAlgorithm, len(algs))
	for i, alg := range algs {
		joseAlgs[i] = jose.SignatureAlgorithm(alg)
	}

	callbackPath := redirect.Path
	if callbackPath == "" {
		callbackPath = "/"
	}

	return &Client{
		cfg:          cfg,
		callbackPath: callbackPath,
		md:           md,
		authURL:      md.authURL,
		algs:         algs,
		joseAlgs:     joseAlgs,
		keys:         newKeySet(fetch, md.JWKSURI, cfg.Now),
		send:         &send,
		now:          cfg.Now,
	}, nil
}
