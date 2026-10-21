// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/hyperscale-stack/security"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

const tracerName = "github.com/hyperscale-stack/security/session"

// ErrNoSession is returned by [Manager.Get] when the request carries no
// session cookie (or one that fails to decode).
var ErrNoSession = errors.New("session: no session on request")

// ErrCookieTooLarge is returned by [Manager.Login], [Manager.Touch] and
// [Manager.Rotate] when the session cookie would exceed [MaxCookieSize]:
// user agents ignore such a cookie, so the session would be lost silently.
// Nothing is written. Keep Values small.
var ErrCookieTooLarge = errors.New("session: cookie larger than 4096 bytes")

// Manager owns the session lifecycle on top of a cookie. It writes the
// cookie through a [security.Carrier] and reads it through the carrier's
// [CookieReader] accessor, so it works behind the HTTP adapter (httpsec)
// without importing it.
//
// Cookie security defaults are conservative: Secure, HttpOnly, SameSite=Lax.
type Manager struct {
	codec       *Codec
	cookieName  string
	path        string
	domain      string
	secure      bool
	httpOnly    bool
	sameSite    http.SameSite
	ttl         time.Duration
	idleTimeout time.Duration
	clock       func() time.Time
	purpose     string
	validator   func(ctx context.Context, s *Session) error
	nameSet     bool
}

// MaxCookieSize bounds a session cookie: the name and value of a cookie
// together may not exceed 4096 octets, or user agents ignore it
// (draft-ietf-httpbis-rfc6265bis §5.6).
const MaxCookieSize = 4096

// maxPurposeLength and maxCookieNameLength bound what the AEAD associated
// data length-prefixes; maxAttributeLength is the longest Path or Domain a
// user agent keeps (rfc6265bis §5.6); maxSessionCookies bounds the cookies
// of the session's name one request may make the Manager open.
const (
	maxPurposeLength    = 255
	maxCookieNameLength = 256
	maxAttributeLength  = 1024
	maxSessionCookies   = 4
)

// Option configures a [Manager].
type Option func(*Manager)

// WithCookieName overrides the cookie name. Default: "__Host-session" when
// the cookie is Secure with Path=/ and no Domain — a sibling host cannot
// then plant a cookie that shadows it (draft-ietf-httpbis-rfc6265bis
// §4.1.3.2) — else "__Secure-session" when it is Secure, else "session".
// An explicit name must be an RFC 6265 token of at most 256 bytes whose
// prefix rules the configuration satisfies: "__Host-" requires Secure,
// Path=/ and no Domain, "__Secure-" requires Secure (prefixes are matched
// case-insensitively, like user agents do). One cookie name per Manager per
// host: __Host- cookies ignore the port.
func WithCookieName(name string) Option {
	return func(m *Manager) {
		m.cookieName = name
		m.nameSet = true
	}
}

// WithPath overrides the cookie Path attribute. Default: "/".
func WithPath(path string) Option {
	return func(m *Manager) { m.path = path }
}

// WithDomain sets the cookie Domain attribute. Default: empty (host-only).
// A Domain rules out the __Host- name: a sibling host can then plant a
// cookie of the session's name, which signs a browser without a session
// into the planted one (login CSRF).
func WithDomain(domain string) Option {
	return func(m *Manager) { m.domain = domain }
}

// WithSecure overrides the Secure attribute. Default: true. Disable it ONLY
// for local plain-HTTP development.
func WithSecure(secure bool) Option {
	return func(m *Manager) { m.secure = secure }
}

// WithSameSite overrides the SameSite attribute. Default: http.SameSiteLaxMode.
func WithSameSite(mode http.SameSite) Option {
	return func(m *Manager) { m.sameSite = mode }
}

// WithTTL overrides the absolute session lifetime: a session expires at
// CreatedAt + TTL, whatever happens in between (Rotate and Touch never
// extend it), and a cookie issued under a longer TTL expires at
// CreatedAt + the current TTL. Raising the TTL does not extend issued
// sessions. Default: 24h.
func WithTTL(ttl time.Duration) Option {
	return func(m *Manager) { m.ttl = ttl }
}

// WithIdleTimeout enables an idle-timeout: a session whose cookie was not
// written (Login, Touch, Rotate) for longer than d is treated as expired —
// Get alone does not slide the window: call [Manager.Touch] on the requests
// that count as activity. Default: 0 (disabled).
func WithIdleTimeout(d time.Duration) Option {
	return func(m *Manager) { m.idleTimeout = d }
}

// WithClock injects a clock for deterministic tests. Default: time.Now.
func WithClock(now func() time.Time) Option {
	return func(m *Manager) {
		if now != nil {
			m.clock = now
		}
	}
}

// WithPurpose binds the Manager's cookies to purpose — e.g. the application
// or realm name — in the AEAD associated data: a cookie sealed by another
// Manager that shares the keys and the cookie name (another application,
// another path) never opens here, nor does one of this Manager open there.
// Default: "". It panics on a purpose longer than 255 bytes.
func WithPurpose(purpose string) Option {
	if len(purpose) > maxPurposeLength {
		panic(fmt.Sprintf("session: WithPurpose: purpose of %d bytes, at most %d", len(purpose), maxPurposeLength))
	}

	return func(m *Manager) { m.purpose = purpose }
}

// WithValidator registers a server-side check run by [Manager.Get] — and so
// by the [Extractor] and [Manager.Rotate] — on every decoded, unexpired
// session: the way to revoke stateless sessions before they expire. Record,
// say, a fingerprint of the session ID in a deny-list at logout (keep it
// until the session's deadline) or the time of a user's last password
// change, and refuse the sessions that match. The validator runs on every
// request: cache its lookups.
//
// An error refuses the session: Get returns [ErrNoSession] wrapping it, and
// the Extractor finds no session. An error wrapping [security.ErrUnavailable]
// — the revocation store is down — is returned as is and propagated by the
// Extractor, so the transports answer 503 instead of signing everyone out.
// It panics on a nil validator.
func WithValidator(validate func(ctx context.Context, s *Session) error) Option {
	if validate == nil {
		panic("session: WithValidator: nil validator")
	}

	return func(m *Manager) { m.validator = validate }
}

// NewManager builds a [Manager] sealing sessions with codec. It panics on a
// configuration a user agent would refuse or that cannot work — a nil
// codec, an invalid cookie name, path or domain, a cookie prefix whose rules
// the attributes break, SameSite=None without Secure (user agents drop it),
// a TTL that is not positive, a negative idle timeout: it is static
// configuration, refused at start-up rather than as silently lost sessions.
func NewManager(codec *Codec, opts ...Option) *Manager {
	m := &Manager{
		codec:    codec,
		path:     "/",
		secure:   true,
		httpOnly: true,
		sameSite: http.SameSiteLaxMode,
		ttl:      24 * time.Hour,
		clock:    time.Now,
	}

	for _, o := range opts {
		o(m)
	}

	if !m.nameSet {
		m.cookieName = m.defaultCookieName()
	}

	if err := m.check(); err != nil {
		panic("session: NewManager: " + err.Error())
	}

	return m
}

// defaultCookieName is the strongest prefixed name the configuration
// allows.
func (m *Manager) defaultCookieName() string {
	switch {
	case m.secure && m.path == "/" && m.domain == "":
		return "__Host-" + schemeName
	case m.secure:
		return "__Secure-" + schemeName
	default:
		return schemeName
	}
}

// check refuses a configuration that cannot work.
func (m *Manager) check() error {
	switch {
	case m.codec == nil:
		return errors.New("nil Codec")
	case m.ttl <= 0:
		return fmt.Errorf("TTL %s: it must be positive", m.ttl)
	case m.idleTimeout < 0:
		return fmt.Errorf("idle timeout %s: it must not be negative", m.idleTimeout)
	}

	return m.checkCookie()
}

// checkCookie refuses cookie attributes a user agent would refuse or drop.
func (m *Manager) checkCookie() error {
	name := strings.ToLower(m.cookieName)

	switch {
	case probe(m.cookieName, "", "").Valid() != nil:
		return fmt.Errorf("invalid cookie name %q: an RFC 6265 token is required", m.cookieName)
	case len(m.cookieName) > maxCookieNameLength:
		return fmt.Errorf("cookie name of %d bytes, at most %d", len(m.cookieName), maxCookieNameLength)
	case !strings.HasPrefix(m.path, "/") || len(m.path) > maxAttributeLength ||
		probe("n", m.path, "").Valid() != nil:
		return fmt.Errorf("invalid cookie path %q: an absolute path of at most %d bytes is required", m.path, maxAttributeLength)
	case m.domain != "" && (len(m.domain) > maxAttributeLength || probe("n", "", m.domain).Valid() != nil):
		return fmt.Errorf("invalid cookie domain %q", m.domain)
	case strings.HasPrefix(name, "__host-") && (!m.secure || m.path != "/" || m.domain != ""):
		return fmt.Errorf("a __Host- cookie (%q) requires Secure, Path=/ and no Domain", m.cookieName)
	case strings.HasPrefix(name, "__secure-") && !m.secure:
		return fmt.Errorf("a __Secure- cookie (%q) requires Secure", m.cookieName)
	case m.sameSite == http.SameSiteNoneMode && !m.secure:
		return errors.New("SameSite=None requires Secure: user agents drop the cookie otherwise")
	}

	return nil
}

// probe is a cookie whose name, path or domain http.Cookie.Valid checks
// (RFC 6265 §4.1.1 token, path and domain syntax).
func probe(name, path, domain string) *http.Cookie {
	return &http.Cookie{
		Name: name, Value: "v", Path: path, Domain: domain,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	}
}

// Login mints a fresh authenticated session for principal, stores its
// subject under the "sub" value, and writes the session cookie via the
// carrier. Any prior session is replaced (a fresh ID defeats fixation).
//
// A nil principal opens a session without a subject — no "sub" value, not
// signed in — such as the one a sign-in form takes its CSRF token from:
// open it on a dedicated Manager that no [Extractor] reads (see
// [VerifyCSRF]), never on the Manager behind the Engine.
func (m *Manager) Login(ctx context.Context, c security.Carrier, principal security.Principal) (*Session, error) {
	_, span := otel.Tracer(tracerName).Start(ctx, "session.Manager.Login")
	defer span.End()

	now := m.clock()

	s, err := newSession(now, m.ttl)
	if err != nil {
		return nil, fmt.Errorf("session: mint: %w", err)
	}

	if principal != nil {
		s.Values["sub"] = principal.Subject()
	}

	if err := m.writeCookie(c, s); err != nil {
		return nil, err
	}

	span.SetAttributes(attribute.String("session.id_hash", hashID(s.ID)))

	return s, nil
}

// Get decodes and validates the session carried by the request's cookie,
// read through the carrier's [CookieReader] accessor — never from a header
// field or the URL. It returns [ErrNoSession] when the cookie is absent or
// undecodable (wrapping [ErrDecode]) or the carrier exposes no cookies, and
// an error wrapping [security.ErrTokenExpired] when the session is past its
// deadline — the earlier of its ExpiresAt and CreatedAt + the Manager's TTL
// — or its idle timeout. A validator ([WithValidator]) then decides; an
// error wrapping [security.ErrUnavailable] means the session could not be
// checked: answer 503, do not sign the user out. When several cookies of
// the session's name open as valid sessions — copies of one session
// included — the request is ambiguous and Get returns [ErrNoSession]: after
// changing [WithDomain] or [WithPath] while the cookie keeps its name,
// clear each cookie of the earlier Domain or Path once with Max-Age=0. On
// success Get refreshes LastAccessed in memory but does NOT rewrite the
// cookie — call [Manager.Touch] when sliding expiry is desired.
func (m *Manager) Get(ctx context.Context, c security.Carrier) (*Session, error) {
	_, span := otel.Tracer(tracerName).Start(ctx, "session.Manager.Get")
	defer span.End()

	cookies, ok := c.(CookieReader)
	if !ok {
		return nil, fmt.Errorf("%w: the carrier exposes no cookies", ErrNoSession)
	}

	s, err := m.pick(ctx, cookies.CookiesNamed(m.cookieName))
	if err != nil {
		return nil, err
	}

	s.LastAccessed = m.clock()
	span.SetAttributes(attribute.String("session.id_hash", hashID(s.ID)))

	return s, nil
}

// pick returns the one valid session among the cookies of the session's
// name. Several cookies of one name come from a cookie tossed by a sibling
// host or a more specific path, or from a stale configuration: when more
// than one is a valid session the request is ambiguous and has none — a
// tossed cookie next to the user's own denies the session. A browser
// without a session of its own carries the tossed cookie alone, and is
// signed into the planted session (login CSRF): only a __Host- name, which
// no other host can set, prevents that. Copies of one session count as
// several: they can differ (a copy planted before a sign-in without
// Rotate), and nothing tells which one the browser meant. Cookies that do
// not open or are expired do not count. An unavailable validator ends the
// search.
func (m *Manager) pick(ctx context.Context, found []*http.Cookie) (*Session, error) {
	if len(found) == 0 {
		return nil, ErrNoSession
	}

	if len(found) > maxSessionCookies {
		return nil, fmt.Errorf("%w: %d cookies of the session's name", ErrNoSession, len(found))
	}

	var (
		chosen   *Session
		firstErr error
	)

	for _, cookie := range found {
		s, err := m.load(ctx, cookie.Value)

		switch {
		case err == nil && chosen != nil:
			return nil, fmt.Errorf("%w: several valid session cookies", ErrNoSession)
		case err == nil:
			chosen = s
		case errors.Is(err, security.ErrUnavailable):
			return nil, err
		case firstErr == nil:
			firstErr = err
		}
	}

	if chosen == nil {
		return nil, firstErr
	}

	return chosen, nil
}

// load opens one cookie value and checks the session's deadline, idle
// timeout and validator.
func (m *Manager) load(ctx context.Context, value string) (*Session, error) {
	if value == "" {
		return nil, ErrNoSession
	}

	s, err := m.codec.open(value, m.cookieName, m.purpose)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoSession, err)
	}

	now := m.clock()
	if now.After(m.deadline(s)) || s.IdleExpired(now, m.idleTimeout) {
		return nil, fmt.Errorf("session: %w", security.ErrTokenExpired)
	}

	s.ExpiresAt = m.deadline(s) // the enforced deadline, earlier after a TTL decrease

	if err := m.validate(ctx, s); err != nil {
		return nil, err
	}

	return s, nil
}

// deadline is the instant s expires: the earlier of the ExpiresAt it
// carries and CreatedAt + the Manager's TTL (decision: the absolute
// lifetime is enforced on every read, whatever the cookie says).
func (m *Manager) deadline(s *Session) time.Time {
	if limit := s.CreatedAt.Add(m.ttl); limit.Before(s.ExpiresAt) {
		return limit
	}

	return s.ExpiresAt
}

// validate runs the validator, if any.
func (m *Manager) validate(ctx context.Context, s *Session) error {
	if m.validator == nil {
		return nil
	}

	err := m.validator(ctx, s)

	switch {
	case err == nil:
		return nil
	case errors.Is(err, security.ErrUnavailable):
		return fmt.Errorf("session: validator: %w", err)
	default:
		return fmt.Errorf("%w: refused by the validator: %w", ErrNoSession, err)
	}
}

// Touch re-writes the cookie with a refreshed LastAccessed, implementing
// sliding-window idle expiry. Call it after a successful Get when the
// idle-timeout should reset on activity. It never extends the absolute
// lifetime: the cookie expires at the session's deadline, and a session at
// or past it is not written ([security.ErrTokenExpired]). A nil session
// fails with [ErrNoSession].
func (m *Manager) Touch(ctx context.Context, c security.Carrier, s *Session) error {
	_, span := otel.Tracer(tracerName).Start(ctx, "session.Manager.Touch")
	defer span.End()

	if s == nil {
		return ErrNoSession
	}

	s.LastAccessed = m.clock()

	return m.writeCookie(c, s)
}

// Rotate issues a new session ID and CSRF token for the current session
// while preserving its Values — the defense against session fixation after
// a privilege change within a session (step-up authentication). It never
// extends the absolute lifetime: the rotated session keeps the creation
// time and deadline of the current one. To start a new lifetime — at
// sign-in — call [Manager.Login], which mints a fresh session.
func (m *Manager) Rotate(ctx context.Context, c security.Carrier) (*Session, error) {
	_, span := otel.Tracer(tracerName).Start(ctx, "session.Manager.Rotate")
	defer span.End()

	current, err := m.Get(ctx, c)
	if err != nil {
		return nil, err
	}

	rotated, err := newSession(m.clock(), m.ttl)
	if err != nil {
		return nil, fmt.Errorf("session: mint: %w", err)
	}

	rotated.Values = current.Values
	rotated.CreatedAt = current.CreatedAt
	rotated.ExpiresAt = m.deadline(current)

	if err := m.writeCookie(c, rotated); err != nil {
		return nil, err
	}

	span.SetAttributes(
		attribute.String("session.old_id_hash", hashID(current.ID)),
		attribute.String("session.new_id_hash", hashID(rotated.ID)),
	)

	return rotated, nil
}

// Logout clears the session cookie by writing an immediately-expired one.
func (m *Manager) Logout(ctx context.Context, c security.Carrier) {
	_, span := otel.Tracer(tracerName).Start(ctx, "session.Manager.Logout")
	defer span.End()

	//nolint:gosec // G124: Secure/HttpOnly/SameSite come from the Manager config (secure-by-default: Secure, HttpOnly, SameSiteLax)
	expired := &http.Cookie{
		Name:     m.cookieName,
		Value:    "",
		Path:     m.path,
		Domain:   m.domain,
		Secure:   m.secure,
		HttpOnly: m.httpOnly,
		SameSite: m.sameSite,
		MaxAge:   -1, // tell the browser to delete it now
	}

	c.Add("Set-Cookie", expired.String())
}

// CookieName returns the configured cookie name (handy for extractors and
// tests).
func (m *Manager) CookieName() string { return m.cookieName }

// writeCookie seals s and stages a Set-Cookie header on the carrier. The
// cookie — and the ExpiresAt it carries — lasts until the session's
// deadline; a session at or past it is not written.
func (m *Manager) writeCookie(c security.Carrier, s *Session) error {
	// Derived from the injected clock, not time.Now, so tests driving a
	// fixed clock observe a coherent cookie lifetime.
	now := m.clock()

	deadline := m.deadline(s)
	if !now.Before(deadline) {
		return fmt.Errorf("session: %w", security.ErrTokenExpired)
	}

	s.ExpiresAt = deadline

	value, err := m.codec.seal(s, m.cookieName, m.purpose)
	if err != nil {
		return fmt.Errorf("session: encode: %w", err)
	}

	if size := len(m.cookieName) + len(value); size > MaxCookieSize {
		return fmt.Errorf("%w: %d bytes", ErrCookieTooLarge, size)
	}

	//nolint:gosec // G124: Secure/HttpOnly/SameSite come from the Manager config (secure-by-default: Secure, HttpOnly, SameSiteLax)
	cookie := &http.Cookie{
		Name:     m.cookieName,
		Value:    value,
		Path:     m.path,
		Domain:   m.domain,
		Secure:   m.secure,
		HttpOnly: m.httpOnly,
		SameSite: m.sameSite,
		Expires:  deadline,
		// Rounded up: in net/http a MaxAge of 0 means "no attribute".
		MaxAge: int(math.Ceil(deadline.Sub(now).Seconds())),
	}

	c.Add("Set-Cookie", cookie.String())

	return nil
}

// hashID returns a short, non-reversible fingerprint of a session ID for
// OTel attributes — the raw ID is a credential and must never hit a trace
// backend.
func hashID(id string) string {
	sum := sha256.Sum256([]byte(id))

	return hex.EncodeToString(sum[:8])
}
