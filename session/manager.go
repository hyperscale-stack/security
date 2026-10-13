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
	"time"

	"github.com/hyperscale-stack/security"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

const tracerName = "github.com/hyperscale-stack/security/session"

// ErrNoSession is returned by [Manager.Get] when the request carries no
// session cookie (or one that fails to decode).
var ErrNoSession = errors.New("session: no session on request")

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
}

// MaxCookieSize bounds a session cookie: the name and value of a cookie
// together may not exceed 4096 octets, or user agents ignore it
// (draft-ietf-httpbis-rfc6265bis §5.6).
const MaxCookieSize = 4096

// maxPurposeLength and maxCookieNameLength bound what the AEAD associated
// data length-prefixes.
const (
	maxPurposeLength    = 255
	maxCookieNameLength = 256
)

// Option configures a [Manager].
type Option func(*Manager)

// WithCookieName overrides the cookie name. Default: "session".
func WithCookieName(name string) Option {
	return func(m *Manager) { m.cookieName = name }
}

// WithPath overrides the cookie Path attribute. Default: "/".
func WithPath(path string) Option {
	return func(m *Manager) { m.path = path }
}

// WithDomain sets the cookie Domain attribute. Default: empty (host-only).
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

// NewManager builds a [Manager] sealing sessions with codec.
func NewManager(codec *Codec, opts ...Option) *Manager {
	m := &Manager{
		codec:      codec,
		cookieName: schemeName,
		path:       "/",
		secure:     true,
		httpOnly:   true,
		sameSite:   http.SameSiteLaxMode,
		ttl:        24 * time.Hour,
		clock:      time.Now,
	}

	for _, o := range opts {
		o(m)
	}

	if len(m.cookieName) > maxCookieNameLength {
		panic(fmt.Sprintf("session: NewManager: cookie name of %d bytes, at most %d", len(m.cookieName), maxCookieNameLength))
	}

	return m
}

// Login mints a fresh authenticated session for principal, stores its
// subject under the "sub" value, and writes the session cookie via the
// carrier. Any prior session is replaced (a fresh ID defeats fixation).
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
// checked: answer 503, do not sign the user out. On success Get refreshes
// LastAccessed in memory but does NOT rewrite the cookie — call
// [Manager.Touch] when sliding expiry is desired.
func (m *Manager) Get(ctx context.Context, c security.Carrier) (*Session, error) {
	_, span := otel.Tracer(tracerName).Start(ctx, "session.Manager.Get")
	defer span.End()

	cookies, ok := c.(CookieReader)
	if !ok {
		return nil, fmt.Errorf("%w: the carrier exposes no cookies", ErrNoSession)
	}

	found := cookies.CookiesNamed(m.cookieName)
	if len(found) == 0 || found[0].Value == "" {
		return nil, ErrNoSession
	}

	s, err := m.codec.open(found[0].Value, m.cookieName, m.purpose)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoSession, err)
	}

	now := m.clock()
	if now.After(m.deadline(s)) || s.IdleExpired(now, m.idleTimeout) {
		return nil, fmt.Errorf("session: %w", security.ErrTokenExpired)
	}

	if err := m.validate(ctx, s); err != nil {
		return nil, err
	}

	s.LastAccessed = now
	span.SetAttributes(attribute.String("session.id_hash", hashID(s.ID)))

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
