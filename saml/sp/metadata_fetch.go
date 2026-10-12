// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/hyperscale-stack/security/outbound"
)

// Refresh policy of a [MetadataSource]; the zero fields of
// [MetadataSourceConfig] take these values.
const (
	// DefaultMetadataRefresh is the refresh interval of metadata that sets
	// no cacheDuration.
	DefaultMetadataRefresh = time.Hour
	// DefaultMetadataMinRefresh and DefaultMetadataMaxRefresh clamp the
	// refresh interval a document's cacheDuration asks for.
	DefaultMetadataMinRefresh = 5 * time.Minute
	DefaultMetadataMaxRefresh = 24 * time.Hour
	// DefaultMetadataMaxStale is how long the last metadata successfully
	// fetched keeps being used while refreshes fail.
	DefaultMetadataMaxStale = 7 * 24 * time.Hour
	// DefaultMetadataRetryInterval spaces the attempts after a failure.
	DefaultMetadataRetryInterval = time.Minute
)

// URL schemes.
const (
	schemeHTTPS = "https"
	schemeHTTP  = "http"
)

// Bounds of the MetadataSourceConfig durations.
const (
	minMetadataRefresh     = time.Minute
	maxMetadataRefresh     = 30 * 24 * time.Hour
	maxMetadataStale       = 365 * 24 * time.Hour
	minMetadataRetry       = time.Second
	metadataAcceptedMedias = "application/samlmetadata+xml, application/xml;q=0.9, text/xml;q=0.8"
)

// FetchOptions configures [FetchIdentityProviderMetadata].
type FetchOptions struct {
	// EntityID, when set, pins the entity ID the document must describe;
	// it also selects the entity of an aggregate.
	EntityID string

	// Outbound is the network policy of the request. Its zero value is
	// the strictest: https only, publicly routable destinations only
	// (judged on the address dialed), no redirect, a 10-second timeout.
	// Exempt an on-premises IdP's subnet in AllowedPrefixes and pin its
	// host in CheckURL; see the outbound package.
	Outbound outbound.Policy

	// MaxSize caps the document (0 means DefaultMetadataMaxSize); the
	// effective cap is the smaller of MaxSize and Outbound.MaxResponseBytes,
	// counted after any transparent decompression.
	MaxSize int64

	// Now is the clock checking validUntil (nil means time.Now).
	Now func() time.Time
}

// FetchIdentityProviderMetadata downloads the IdP metadata published at
// metadataURL and imports it with [ParseIdentityProviderMetadata].
//
// The URL is configuration — the application's, or a tenant
// administrator's — never a value taken from a SAML message or a request.
// The request is a GET, through an [outbound.NewClient] client enforcing
// opts.Outbound, with no credentials and no cookies; only a 200 answer is
// read. Fetching is the act of trust: it rests on TLS to the configured
// host and on the pinned entity ID, an embedded signature being ignored as
// for imported metadata.
//
// Errors: an unusable URL or options match [ErrInvalidConfig]; a refused
// request (the outbound errors stay matchable), a network failure or
// another status match [ErrMetadataUnavailable]; the document's problems
// match [ErrInvalidMetadata] or [ErrMetadataExpired]. No error carries the
// response body. A refused destination is never named; the errors of
// allowed destinations may name their address.
func FetchIdentityProviderMetadata(ctx context.Context, metadataURL string, opts FetchOptions) (*IdentityProvider, error) {
	f, err := newMetadataFetcher(metadataURL, opts.Outbound, opts.MaxSize)
	if err != nil {
		return nil, err
	}

	now := opts.Now
	if now == nil {
		now = time.Now
	}

	return f.fetch(ctx, opts.EntityID, now)
}

// metadataFetcher downloads the metadata of one URL with one client.
type metadataFetcher struct {
	url     string
	client  *http.Client
	maxSize int64
}

func newMetadataFetcher(rawURL string, policy outbound.Policy, maxSize int64) (*metadataFetcher, error) {
	if err := validateMetadataURL(rawURL, policy.AllowHTTP); err != nil {
		return nil, err
	}

	switch {
	case maxSize < 0:
		return nil, fmt.Errorf("%w: negative metadata MaxSize", ErrInvalidConfig)
	case maxSize == 0:
		maxSize = DefaultMetadataMaxSize
	}

	limit := policy.MaxResponseBytes
	if limit == 0 {
		limit = outbound.DefaultMaxResponseBytes
	}

	policy.MaxResponseBytes = min(limit, maxSize) // NewClient copies AllowedPrefixes

	client, err := outbound.NewClient(policy)
	if err != nil {
		return nil, fmt.Errorf("%w: metadata outbound policy: %w", ErrInvalidConfig, err)
	}

	return &metadataFetcher{url: rawURL, client: client, maxSize: policy.MaxResponseBytes}, nil
}

// validateMetadataURL requires an absolute https URL (http with AllowHTTP)
// without credentials or fragment.
func validateMetadataURL(raw string, allowHTTP bool) error {
	u, err := url.Parse(raw)

	switch {
	case err != nil || !u.IsAbs() || u.Host == "" || u.Opaque != "":
		return fmt.Errorf("%w: the metadata URL must be an absolute URL", ErrInvalidConfig)
	case u.Scheme != schemeHTTPS && (u.Scheme != schemeHTTP || !allowHTTP):
		return fmt.Errorf("%w: the metadata URL must be https", ErrInvalidConfig)
	case u.User != nil:
		return fmt.Errorf("%w: the metadata URL must not carry credentials", ErrInvalidConfig)
	case u.Fragment != "" || u.RawFragment != "":
		return fmt.Errorf("%w: the metadata URL must not carry a fragment", ErrInvalidConfig)
	}

	return nil
}

// fetch downloads and imports the document.
func (f *metadataFetcher) fetch(ctx context.Context, entityID string, now func() time.Time) (_ *IdentityProvider, err error) {
	ctx, span := startSpan(ctx, "samlsp.FetchMetadata")
	defer func() { endSpan(span, err) }()

	body, err := f.download(ctx)
	if err != nil {
		return nil, err
	}

	return ParseIdentityProviderMetadata(body, MetadataOptions{EntityID: entityID, Now: now, MaxSize: f.maxSize})
}

// download GETs the document; the outbound client bounds the exchange.
func (f *metadataFetcher) download(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %w", ErrMetadataUnavailable, err)
	}

	req.Header.Set("Accept", metadataAcceptedMedias)

	// The URL is configuration, and the client enforces the outbound
	// policy on every connection.
	resp, err := f.client.Do(req) //nolint:gosec // G107/G704: SSRF handled by the outbound policy
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMetadataUnavailable, err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP status %d", ErrMetadataUnavailable, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: read body: %w", ErrMetadataUnavailable, err)
	}

	return body, nil
}

// MetadataSourceConfig configures a [MetadataSource].
type MetadataSourceConfig struct {
	// URL is the metadata URL: configuration, never a value taken from a
	// SAML message or a request. https, or http with Outbound.AllowHTTP.
	// Required.
	URL string

	// EntityID pins the IdP entity ID: a document describing another
	// entity is refused, and the last good one kept. Required.
	EntityID string

	// Outbound is the network policy of the requests (see FetchOptions).
	Outbound outbound.Policy

	// MaxSize caps the document (see FetchOptions).
	MaxSize int64

	// MinRefresh and MaxRefresh clamp the refresh interval, which is the
	// document's cacheDuration (DefaultMetadataRefresh when absent),
	// shortened to its validUntil: DefaultMetadataMinRefresh and
	// DefaultMetadataMaxRefresh when zero; MinRefresh at least a minute,
	// MaxRefresh at most 30 days.
	MinRefresh time.Duration
	MaxRefresh time.Duration

	// MaxStale is how long the last metadata successfully fetched keeps
	// being used while refreshes fail (DefaultMetadataMaxStale when zero;
	// between MaxRefresh and a year). It never extends a document past its
	// validUntil.
	MaxStale time.Duration

	// RetryInterval spaces the attempts after a failure
	// (DefaultMetadataRetryInterval when zero; between a second and
	// MaxRefresh).
	RetryInterval time.Duration

	// Now is the clock (nil means time.Now).
	Now func() time.Time
}

// withDefaults returns cfg with its zero durations and clock defaulted.
func (cfg MetadataSourceConfig) withDefaults() MetadataSourceConfig {
	if cfg.MinRefresh == 0 {
		cfg.MinRefresh = DefaultMetadataMinRefresh
	}

	if cfg.MaxRefresh == 0 {
		cfg.MaxRefresh = DefaultMetadataMaxRefresh
	}

	if cfg.MaxStale == 0 {
		cfg.MaxStale = DefaultMetadataMaxStale
	}

	if cfg.RetryInterval == 0 {
		cfg.RetryInterval = DefaultMetadataRetryInterval
	}

	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	return cfg
}

// validate checks a defaulted configuration (the URL and the policy are
// checked by newMetadataFetcher).
func (cfg MetadataSourceConfig) validate() error {
	if err := validateEntityID(cfg.EntityID); err != nil {
		return fmt.Errorf("%w: metadata source entity ID: %w", ErrInvalidConfig, err)
	}

	switch {
	case cfg.MinRefresh < minMetadataRefresh || cfg.MaxRefresh < cfg.MinRefresh || cfg.MaxRefresh > maxMetadataRefresh:
		return fmt.Errorf("%w: metadata refresh bounds must satisfy 1m <= MinRefresh <= MaxRefresh <= 720h", ErrInvalidConfig)
	case cfg.MaxStale < cfg.MaxRefresh || cfg.MaxStale > maxMetadataStale:
		return fmt.Errorf("%w: metadata MaxStale must be between MaxRefresh and a year", ErrInvalidConfig)
	case cfg.RetryInterval < minMetadataRetry || cfg.RetryInterval > cfg.MaxRefresh:
		return fmt.Errorf("%w: metadata RetryInterval must be between 1s and MaxRefresh", ErrInvalidConfig)
	}

	return nil
}

// MetadataSource keeps the [IdentityProvider] published at one trusted
// metadata URL up to date, for a [ConnectionResolver] to use:
//
//	idp, err := source.IdentityProvider(ctx)
//
// It fetches lazily, on the first call and whenever a call finds the
// refresh due: concurrent callers share one fetch (single-flight), and
// failed attempts are spaced by RetryInterval, so traffic cannot make it
// fetch more often; no response content ever triggers a fetch. A fetch
// runs detached from the context of the caller that started it, bounded
// by the outbound timeout, so that a caller giving up abandons it neither
// for the others nor for the rate limit; there is no background goroutine.
//
// Keys and endpoints change only through a document successfully fetched
// from the URL, valid, and describing the pinned entity: an IdP key
// rollover is picked up at the next refresh. When refreshes fail, the last
// such document keeps being served for at most MaxStale after it was
// fetched, never past its validUntil (Metadata §4.3.2, errata E94); then
// IdentityProvider fails closed with [ErrMetadataExpired].
//
// A MetadataSource is safe for concurrent use.
type MetadataSource struct {
	fetcher  *metadataFetcher
	entityID string
	cfg      MetadataSourceConfig

	mu        sync.Mutex
	idp       *IdentityProvider // last good document, nil before the first
	fetchedAt time.Time         // when idp was fetched
	refreshAt time.Time         // when idp is due for refresh
	failedAt  time.Time         // last failed attempt (a success always comes RetryInterval later)
	lastErr   error             // error of the last failed attempt, errNotFetched before any
	inflight  *metadataFetch
}

// errNotFetched reports that no metadata was fetched yet.
var errNotFetched = fmt.Errorf("%w: not fetched yet", ErrMetadataUnavailable)

// metadataFetch is a fetch in flight; done is closed once err is set.
type metadataFetch struct {
	done chan struct{}
	err  error
}

// NewMetadataSource validates cfg and returns a MetadataSource; it does not
// access the network.
func NewMetadataSource(cfg MetadataSourceConfig) (*MetadataSource, error) {
	cfg = cfg.withDefaults()

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	f, err := newMetadataFetcher(cfg.URL, cfg.Outbound, cfg.MaxSize)
	if err != nil {
		return nil, err
	}

	return &MetadataSource{fetcher: f, entityID: cfg.EntityID, cfg: cfg, lastErr: errNotFetched}, nil
}

// IdentityProvider returns a copy of the current IdP configuration,
// fetching the metadata first when none was fetched yet or the refresh is
// due (unless a failure occurred less than RetryInterval ago). The error
// of a refresh is returned only when no usable document remains: then it
// matches [ErrMetadataUnavailable], [ErrInvalidMetadata] or
// [ErrMetadataExpired]. When ctx ends before the fetch, its error is
// returned, and the fetch completes for the next callers.
func (s *MetadataSource) IdentityProvider(ctx context.Context) (*IdentityProvider, error) {
	if s.due() {
		if err := s.refresh(ctx); err != nil && ctx.Err() != nil {
			return nil, err
		}
	}

	return s.current()
}

// due reports whether the metadata needs a fetch that the rate limit
// allows. A fetch in flight started under the same conditions, which hold
// until it completes: callers then join it.
func (s *MetadataSource) due() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.cfg.Now()

	if !s.failedAt.IsZero() && now.Before(s.failedAt.Add(s.cfg.RetryInterval)) {
		return false
	}

	return s.idp == nil || !now.Before(s.refreshAt)
}

// refresh starts a fetch, or joins the one in flight, and waits for it or
// for ctx.
func (s *MetadataSource) refresh(ctx context.Context) error {
	s.mu.Lock()

	call := s.inflight
	if call == nil {
		call = &metadataFetch{done: make(chan struct{})}
		s.inflight = call

		go s.fetch(context.WithoutCancel(ctx), call)
	}

	s.mu.Unlock()

	select {
	case <-call.done:
		return call.err
	case <-ctx.Done():
		return fmt.Errorf("samlsp: waiting for the identity provider metadata: %w", ctx.Err())
	}
}

// fetch downloads the metadata and publishes the outcome to call.
func (s *MetadataSource) fetch(ctx context.Context, call *metadataFetch) {
	idp, err := s.fetcher.fetch(ctx, s.entityID, s.cfg.Now)

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.cfg.Now()

	if err == nil {
		s.idp, s.fetchedAt, s.refreshAt = idp, now, now.Add(s.interval(idp, now))
	} else {
		s.failedAt, s.lastErr = now, err
	}

	s.inflight = nil
	call.err = err
	close(call.done)
}

// interval is the refresh interval of idp fetched at fetchedAt: its
// cacheDuration (DefaultMetadataRefresh when absent), shortened to its
// validUntil, clamped to [MinRefresh, MaxRefresh].
func (s *MetadataSource) interval(idp *IdentityProvider, fetchedAt time.Time) time.Duration {
	d := idp.CacheDuration
	if d == 0 {
		d = DefaultMetadataRefresh
	}

	if !idp.ValidUntil.IsZero() {
		d = min(d, idp.ValidUntil.Sub(fetchedAt))
	}

	return min(max(d, s.cfg.MinRefresh), s.cfg.MaxRefresh)
}

// current returns a copy of the last good document while it is usable.
func (s *MetadataSource) current() (*IdentityProvider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.cfg.Now()

	switch {
	case s.idp == nil:
		return nil, s.lastErr
	case s.idp.expired(now):
		return nil, fmt.Errorf("%w: the last document fetched is past its validUntil", ErrMetadataExpired)
	case now.Sub(s.fetchedAt) > s.cfg.MaxStale:
		return nil, fmt.Errorf("%w: not refreshed for over %s", ErrMetadataExpired, s.cfg.MaxStale)
	}

	idp := *s.idp
	idp.SigningCertificates = slices.Clone(s.idp.SigningCertificates)

	return &idp, nil
}
