// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/hyperscale-stack/security/outbound"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// Refresh policy of the remote JWK Set ([NewRemoteJWKS]).
const (
	// DefaultCacheTTL is how long a fetched JWK Set is used before its next
	// use refreshes it, in the background.
	DefaultCacheTTL = 5 * time.Minute
	// MinKeySetRefreshInterval is the least time between two fetch
	// attempts, whatever triggers them — the TTL, a token with an unknown
	// kid, a caller with no usable set: unauthenticated requests cannot
	// make the provider fetch more often.
	MinKeySetRefreshInterval = 10 * time.Second
	// MaxKeySetStaleness is the age after which a JWK Set is no longer
	// used while refreshes fail: a key the issuer withdrew stops verifying
	// at the latest then, and verification fails with ErrKeySetUnavailable.
	MaxKeySetStaleness = 24 * time.Hour
)

// Bounds of a fetch, applied on top of the outbound policy — or of the
// client given with WithHTTPClient.
const (
	// maxKeySetBackoff caps the wait between two failing attempts while a
	// usable set is served; without one, attempts stay
	// MinKeySetRefreshInterval apart.
	maxKeySetBackoff = 5 * time.Minute
	// maxBackoffDoublings bounds the doublings of MinKeySetRefreshInterval:
	// 10 s × 2⁵ already exceeds maxKeySetBackoff, and the shift never
	// overflows however many attempts failed.
	maxBackoffDoublings = 5
	// jwksFetchTimeout bounds a whole fetch.
	jwksFetchTimeout = outbound.DefaultTimeout
	// maxJWKSBytes bounds the document.
	maxJWKSBytes = 1 << 20
)

// Schemes of a JWK Set URL: https, or http with an explicit opt-in.
const (
	schemeHTTPS = "https"
	schemeHTTP  = "http"
)

// defaultMaxRedirects is net/http's redirect limit for a client without
// CheckRedirect, which the pinned copy of a WithHTTPClient client keeps.
const defaultMaxRedirects = 10

// remoteOptions collects the RemoteOptions of NewRemoteJWKS.
type remoteOptions struct {
	client *http.Client
	policy *outbound.Policy
	ttl    time.Duration
}

// RemoteOption configures a remote JWKS provider.
type RemoteOption func(*remoteOptions)

// WithOutboundPolicy sets the SSRF policy of the client that fetches the
// JWK Set (default: the zero [outbound.Policy] — https only, publicly
// routable destinations only, no redirect, no proxy). A JWKS host on a
// private network needs it: exempt its subnet in AllowedPrefixes, give a
// private CA in RootCAs, allow plain http for local development only. The
// provider's own bounds (10 s, 1 MiB) apply on top of the policy's, and
// the redirects MaxRedirects allows are followed within the JWK Set URL's
// origin only (see [NewRemoteJWKS]).
func WithOutboundPolicy(p outbound.Policy) RemoteOption {
	return func(o *remoteOptions) { o.policy = &p }
}

// WithHTTPClient replaces the SSRF-safe client with c — an explicit
// opt-out: c decides which destinations, redirects and proxies are
// allowed, and an http URL is accepted. The provider still bounds each
// fetch (10 s, 1 MiB), follows c's redirects within the JWK Set URL's
// origin only (on a copy of c: c itself is not modified), and refuses a
// response that arrives over http for an https URL (a redirect downgrade
// would let a network attacker serve its own keys). Exclusive with
// WithOutboundPolicy; a nil c panics.
func WithHTTPClient(c *http.Client) RemoteOption {
	if c == nil {
		panic("jwtsec.WithHTTPClient: nil client")
	}

	return func(o *remoteOptions) { o.client = c }
}

// WithCacheTTL sets how long a fetched JWK Set is used before its next use
// refreshes it (default [DefaultCacheTTL]); refreshes stay at least
// [MinKeySetRefreshInterval] apart. A TTL outside (0, MaxKeySetStaleness]
// panics.
func WithCacheTTL(d time.Duration) RemoteOption {
	if d <= 0 || d > MaxKeySetStaleness {
		panic("jwtsec.WithCacheTTL: the TTL must be in (0, MaxKeySetStaleness]")
	}

	return func(o *remoteOptions) { o.ttl = d }
}

// NewRemoteJWKS returns a [JWKSProvider] serving the JSON Web Key Set at
// rawURL (RFC 7517 §5), typically an authorization server's or OpenID
// Provider's jwks_uri.
//
// Fetching: through [outbound.NewClient] — https only, publicly routable
// destinations judged at dial time (no loopback, private network or cloud
// metadata address), no redirect, no proxy, 10 s and 1 MiB per fetch — or
// the policy of [WithOutboundPolicy], or the client of [WithHTTPClient]
// (opt-out). Whatever the client, a redirect it may follow is followed
// within the origin of rawURL only — scheme, host and port (RFC 6454 §4),
// the rule of oidc/client and saml/sp: a hop to another origin fails with
// [outbound.ErrRedirectNotAllowed], so only that origin's keys ever verify
// tokens. The document is strict JSON; each key is validated on its
// own and an unusable one is ignored without discarding the set (RFC 7517
// §5): private or symmetric material, use other than sig, key_ops without
// verify, an unknown key type or curve, RSA outside 2048–8192 bits, an alg
// the key cannot verify. A key without alg gets the algorithm its curve
// implies (EC, Ed25519); an RSA key without alg verifies RS256 when the
// verifier allows it, otherwise the verifier's only RSA algorithm.
//
// Refreshing: the set is fetched on first use, then in the background
// once older than the TTL ([WithCacheTTL]) while the cached set keeps
// serving, and once on a token whose kid it does not hold (key rotation,
// OpenID Connect Core §10.1.1) — at most once per
// [MinKeySetRefreshInterval], all callers sharing one fetch that runs
// without holding any lock and is not aborted when a caller gives up.
// After a failed fetch the cached set keeps serving, attempts backing off
// up to 5 minutes, until it is older than [MaxKeySetStaleness]; without a
// usable set, KeySet fails with [ErrKeySetUnavailable] (callers waiting
// for a fetch stop at their context's end). A fetched set without any
// usable key replaces the previous one: the issuer withdrew its keys.
//
// NewRemoteJWKS fails, wrapping [outbound.ErrURLNotAllowed], on a URL
// that is not absolute https (http with WithOutboundPolicy's AllowHTTP or
// WithHTTPClient), has no host or carries userinfo, and wrapping
// [outbound.ErrInvalidPolicy] on an invalid policy. The provider prints
// its URL without userinfo or query, and so do its errors.
func NewRemoteJWKS(rawURL string, opts ...RemoteOption) (JWKSProvider, error) {
	o := remoteOptions{ttl: DefaultCacheTTL}
	for _, opt := range opts {
		opt(&o)
	}

	if o.client != nil && o.policy != nil {
		panic("jwtsec.NewRemoteJWKS: WithHTTPClient and WithOutboundPolicy are exclusive")
	}

	allowHTTP := o.client != nil || (o.policy != nil && o.policy.AllowHTTP)

	u, err := checkJWKSURL(rawURL, allowHTTP)
	if err != nil {
		return nil, err
	}

	client := o.client
	if client == nil {
		policy := outbound.Policy{}
		if o.policy != nil {
			policy = *o.policy
		}

		if client, err = outbound.NewClient(policy); err != nil {
			return nil, fmt.Errorf("jwt: remote JWKS: %w", err)
		}
	}

	return &remoteJWKS{
		url:       u.String(),
		display:   redactURL(u),
		httpsOnly: u.Scheme == schemeHTTPS,
		client:    pinRedirects(client, u),
		ttl:       o.ttl,
		now:       time.Now,
		timeout:   jwksFetchTimeout,
	}, nil
}

// checkJWKSURL parses rawURL and refuses what can never be fetched safely.
// The errors never quote the URL.
func checkJWKSURL(rawURL string, allowHTTP bool) (*url.URL, error) {
	u, err := url.Parse(rawURL)

	switch {
	case err != nil:
		return nil, fmt.Errorf("jwt: remote JWKS URL: %w: unparsable", outbound.ErrURLNotAllowed)
	case u.User != nil:
		return nil, fmt.Errorf("jwt: remote JWKS URL: %w: userinfo", outbound.ErrURLNotAllowed)
	case u.Host == "":
		return nil, fmt.Errorf("jwt: remote JWKS URL: %w: not an absolute URL", outbound.ErrURLNotAllowed)
	case u.Scheme == schemeHTTPS, u.Scheme == schemeHTTP && allowHTTP:
		return u, nil
	default:
		return nil, fmt.Errorf("jwt: remote JWKS URL: %w: the scheme must be https", outbound.ErrURLNotAllowed)
	}
}

// pinRedirects returns a copy of c whose CheckRedirect applies c's own
// policy — net/http's limit of 10 redirects when c has none — then
// refuses a hop to another origin than u's (see NewRemoteJWKS).
func pinRedirects(c *http.Client, u *url.URL) *http.Client {
	pinned := *c
	next := c.CheckRedirect
	origin := originOf(u)

	pinned.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		switch {
		case next != nil:
			// Returned as is: net/http compares it with ErrUseLastResponse.
			if err := next(req, via); err != nil {
				return err
			}
		case len(via) >= defaultMaxRedirects:
			return fmt.Errorf("%w: stopped after %d redirects", outbound.ErrRedirectNotAllowed, defaultMaxRedirects)
		}

		if originOf(req.URL) != origin {
			return fmt.Errorf("%w: to another origin than the JWK Set URL's", outbound.ErrRedirectNotAllowed)
		}

		return nil
	}

	return &pinned
}

// originOf renders the origin of u (RFC 6454 §4): its scheme (url.Parse
// lower-cases it), its host lower-cased in ASCII only — a host that is not
// ASCII stays its own origin — an IP literal in canonical form, and the
// port as a number, the scheme's default when absent.
func originOf(u *url.URL) string {
	scheme := u.Scheme

	host := asciiLower(u.Hostname())
	if addr, err := netip.ParseAddr(host); err == nil {
		host = addr.String()
	}

	port := u.Port()

	switch {
	case port != "":
		if n, err := strconv.Atoi(port); err == nil {
			port = strconv.Itoa(n)
		}
	case scheme == schemeHTTP:
		port = "80"
	default:
		port = "443"
	}

	return scheme + "://" + net.JoinHostPort(host, port)
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

// redactURL returns u without userinfo, query nor fragment — a query may
// carry an API key — for printing and errors.
func redactURL(u *url.URL) string {
	r := *u
	r.User = nil
	r.Fragment, r.RawFragment = "", ""

	if r.RawQuery != "" {
		r.RawQuery = "REDACTED"
	}

	return r.String()
}

// remoteJWKS is the provider of NewRemoteJWKS. mu guards the state only:
// it is never held during a fetch.
type remoteJWKS struct {
	url       string
	display   string // url without userinfo, query or fragment
	httpsOnly bool   // the URL is https: refuse a response arriving over http
	client    *http.Client
	ttl       time.Duration
	now       func() time.Time // test hook
	timeout   time.Duration    // test hook

	mu          sync.Mutex
	keys        *staticKeySet // last successful fetch, nil before
	fetchedAt   time.Time     // when keys was fetched
	lastAttempt time.Time     // when the last fetch completed
	failures    int           // consecutive failed fetches
	lastErr     error         // error of the last failed fetch
	inflight    *jwksFetch    // the fetch in flight, nil when none
}

// jwksFetch is a fetch in flight; done is closed once it completed.
type jwksFetch struct {
	done chan struct{}
}

// errNoKeySet reports that no JWK Set was retrieved yet.
var errNoKeySet = errors.New("no JWK Set retrieved yet")

// keyRefresher is implemented by providers that can fetch their key set
// again for a kid they do not hold.
type keyRefresher interface {
	refreshKeySet(ctx context.Context) (KeySet, error)
}

// KeySet implements [JWKSProvider]: the cached set when usable — starting
// a background refresh once it is older than the TTL — or, without one,
// the result of a fetch, joined or started, waited for until ctx ends.
func (r *remoteJWKS) KeySet(ctx context.Context) (KeySet, error) {
	r.mu.Lock()

	now := r.now()
	keys := r.usable(now)

	var call *jwksFetch
	if keys == nil || !now.Before(r.fetchedAt.Add(r.ttl)) {
		call = r.start(ctx, now)
	}

	r.mu.Unlock()

	if keys != nil {
		return keys, nil
	}

	return r.await(ctx, call)
}

// refreshKeySet implements keyRefresher: a fetch is started or joined —
// unless the last attempt is too recent — and waited for until ctx ends;
// it returns the usable set then.
func (r *remoteJWKS) refreshKeySet(ctx context.Context) (KeySet, error) {
	r.mu.Lock()
	call := r.start(ctx, r.now())
	r.mu.Unlock()

	return r.await(ctx, call)
}

// await waits for call, when there is one, and returns the usable set.
// Its errors name the redacted URL — they alone do: the fetch errors name
// none.
func (r *remoteJWKS) await(ctx context.Context, call *jwksFetch) (KeySet, error) {
	if call != nil {
		select {
		case <-call.done:
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: %s: waiting for the JWK Set: %w", ErrKeySetUnavailable, r.display, ctx.Err())
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if keys := r.usable(r.now()); keys != nil {
		return keys, nil
	}

	return nil, fmt.Errorf("%w: %s: %w", ErrKeySetUnavailable, r.display, cmp.Or(r.lastErr, errNoKeySet))
}

// usable returns the cached set unless there is none or it is older than
// MaxKeySetStaleness. The caller holds mu.
func (r *remoteJWKS) usable(now time.Time) *staticKeySet {
	if r.keys == nil || now.Sub(r.fetchedAt) > MaxKeySetStaleness {
		return nil
	}

	return r.keys
}

// start returns the fetch in flight, or starts one unless the last attempt
// completed less than wait ago; nil when none may start. The caller holds
// mu.
func (r *remoteJWKS) start(ctx context.Context, now time.Time) *jwksFetch {
	if r.inflight != nil {
		return r.inflight
	}

	if !r.lastAttempt.IsZero() && now.Before(r.lastAttempt.Add(r.wait(now))) {
		return nil
	}

	call := &jwksFetch{done: make(chan struct{})}
	r.inflight = call

	go r.fetch(ctx, call)

	return call
}

// wait returns the least time between the last attempt and the next one:
// MinKeySetRefreshInterval, doubling with consecutive failures up to
// maxKeySetBackoff while a usable set is served — without one, a quick
// retry matters more than sparing the upstream. The caller holds mu.
func (r *remoteJWKS) wait(now time.Time) time.Duration {
	if r.failures == 0 || r.usable(now) == nil {
		return MinKeySetRefreshInterval
	}

	return min(MinKeySetRefreshInterval<<min(r.failures-1, maxBackoffDoublings), maxKeySetBackoff)
}

// fetch downloads the set and publishes the outcome. It runs on its own
// goroutine, on a context detached from the caller's — so that a caller
// giving up neither aborts it for the others nor burns the rate limit —
// bounded by the fetch timeout, in a span of its own linked to the
// caller's.
func (r *remoteJWKS) fetch(parent context.Context, call *jwksFetch) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), r.timeout)
	defer cancel()

	ctx, span := otel.Tracer(tracerName).Start(ctx, "jwtsec.RemoteJWKS.Fetch",
		trace.WithNewRoot(), trace.WithLinks(trace.LinkFromContext(parent)),
		trace.WithAttributes(attribute.String("jwt.jwks.url", r.display)))
	defer span.End()

	keys, ignored, err := r.download(ctx)
	if err != nil {
		// Clipped once: the error is kept and reported on every failing
		// verification, and a transport's may quote what the JWK Set host
		// sent (net/http quotes a malformed status line whole).
		err = clipError(err)

		span.SetStatus(codes.Error, "fetch")
		span.RecordError(err)
	} else {
		span.SetAttributes(attribute.Int("jwt.jwks.keys", len(keys)), attribute.Int("jwt.jwks.ignored", ignored))
	}

	r.mu.Lock()

	now := r.now()
	r.lastAttempt = now

	if err == nil {
		r.keys, r.fetchedAt, r.failures, r.lastErr = &staticKeySet{publics: keys}, now, 0, nil
	} else {
		r.failures++
		r.lastErr = err
	}

	r.inflight = nil
	r.mu.Unlock()

	close(call.done)
}

// download fetches and parses the set. A panic — of a caller-supplied
// transport, of a key parser on a hostile document — is a failed fetch,
// never a crash of the detached goroutine.
func (r *remoteJWKS) download(ctx context.Context) (keys []PublicKey, ignored int, err error) {
	defer func() {
		if p := recover(); p != nil {
			keys, ignored, err = nil, 0, errors.New("the JWK Set fetch panicked")
		}
	}()

	body, err := r.get(ctx)
	if err != nil {
		return nil, 0, err
	}

	return parseJWKS(body)
}

// get performs the request. Its errors name no URL (see withoutURL).
func (r *remoteJWKS) get(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url, nil)
	if err != nil {
		return nil, withoutURL(err)
	}

	req.Header.Set("Accept", "application/jwk-set+json, application/json")

	// The URL comes from the operator; the default client enforces the
	// outbound policy at dial time, WithHTTPClient is the documented
	// opt-out. G704's SSRF heuristic cannot see either.
	resp, err := r.client.Do(req) //nolint:gosec // operator URL; outbound policy by default, documented opt-out
	if err != nil {
		return nil, withoutURL(err)
	}

	defer func() { _ = resp.Body.Close() }()

	if r.httpsOnly && (resp.Request == nil || resp.Request.URL.Scheme != schemeHTTPS) {
		return nil, errors.New("the response did not come over https")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, withoutURL(err)
	}

	if len(body) > maxJWKSBytes {
		return nil, outbound.ErrResponseTooLarge
	}

	return body, nil
}

// withoutURL returns the cause of the *url.Error net/http returns, which
// names the request URL — a redirect target's included — with its user
// name and query (a password alone is masked); the cause stays matchable.
// The provider's errors name its redacted URL instead (see await).
func withoutURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}

	return err
}

// String implements fmt.Stringer with the redacted URL.
func (r *remoteJWKS) String() string { return fmt.Sprintf("jwtsec.RemoteJWKS{URL: %q}", r.display) }

// Format implements fmt.Formatter like String, for every verb: fmt would
// otherwise print the fields, the URL with its query included.
func (r *remoteJWKS) Format(f fmt.State, _ rune) { formatKey(f, r) }

// LogValue implements slog.LogValuer with the redacted URL.
func (r *remoteJWKS) LogValue() slog.Value {
	return slog.GroupValue(slog.String("url", r.display))
}
