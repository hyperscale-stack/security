// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/hyperscale-stack/security/outbound"
)

// Client is the Relying Party of one connection. It is safe for concurrent
// use; the application builds one per connection and keeps it.
type Client struct {
	cfg           Config
	redirect      *url.URL   // the parsed RedirectURL
	redirectQuery url.Values // its query parameters
	md            *providerMetadata
	authURL       *url.URL
	algs          []Algorithm
	joseAlgs      []jose.SignatureAlgorithm
	keys          *keySet      // fetches through the same-origin client
	send          *http.Client // token and UserInfo: credentials, never redirected
	now           func() time.Time
}

// refuseRedirect is the CheckRedirect of credential-bearing requests.
func refuseRedirect(*http.Request, []*http.Request) error {
	return fmt.Errorf("%w: a token or UserInfo request is never redirected", outbound.ErrRedirectNotAllowed)
}

// sameOriginRedirect is the CheckRedirect of the discovery and JWK Set
// requests: it applies next — the outbound policy's hop limit and https to
// http refusal — and refuses a hop to another origin than the first request
// of the exchange. The metadata then comes from the issuer's origin and the
// keys from the jwks_uri's, whose TLS identity OpenID Connect Discovery 1.0
// §7.2 relies on ("the server certificate is valid for the Issuer URL"),
// whatever MaxRedirects allows.
func sameOriginRedirect(next func(*http.Request, []*http.Request) error) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if err := next(req, via); err != nil {
			return err
		}

		if originOf(req.URL) != originOf(via[0].URL) {
			return fmt.Errorf("%w: to another origin than the one requested", outbound.ErrRedirectNotAllowed)
		}

		return nil
	}
}

// originOf renders the origin of u (RFC 6454 §4): its scheme and host
// lower-cased in ASCII only — a host that is not ASCII stays its own origin
// — an IP literal in canonical form, and the port as a number, the
// scheme's default when absent.
func originOf(u *url.URL) string {
	host := asciiLower(u.Hostname())
	if addr, err := netip.ParseAddr(host); err == nil {
		host = addr.String()
	}

	port := effectivePort(u)
	if n, err := strconv.Atoi(port); err == nil {
		port = strconv.Itoa(n)
	}

	return asciiLower(u.Scheme) + "://" + net.JoinHostPort(host, port)
}

// asciiLower maps the ASCII upper-case letters of s to lower case, and
// nothing else (RFC 4790 i;ascii-casemap).
func asciiLower(s string) string {
	b := []byte(s)

	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}

	return string(b)
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
// The keys are fetched on first use. The discovery and JWK Set requests
// follow a redirect only when cfg.Outbound.MaxRedirects allows it, and
// never to another origin than the one requested (see Config.Outbound). To
// pick up changed metadata, build a new Client.
func New(ctx context.Context, cfg Config) (*Client, error) {
	cfg, redirect, err := cfg.normalized()
	if err != nil {
		return nil, err
	}

	base, err := outbound.NewClient(cfg.Outbound)
	if err != nil {
		return nil, fmt.Errorf("%w: Outbound: %w", ErrInvalidConfig, err)
	}

	// Discovery and JWK Set requests carry no credential: they follow the
	// policy's redirects, but only within the origin they were sent to.
	fetch := *base
	fetch.CheckRedirect = sameOriginRedirect(base.CheckRedirect)

	// Token and UserInfo requests carry credentials: they share the
	// policy but never follow a redirect.
	send := *base
	send.CheckRedirect = refuseRedirect

	md, err := discover(ctx, &fetch, cfg.Issuer, cfg.Outbound.AllowHTTP)
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

	return &Client{
		cfg:           cfg,
		redirect:      redirect,
		redirectQuery: redirect.Query(),
		md:            md,
		authURL:       md.authURL,
		algs:          algs,
		joseAlgs:      joseAlgs,
		keys:          newKeySet(&fetch, md.JWKSURI, cfg.Now),
		send:          &send,
		now:           cfg.Now,
	}, nil
}
