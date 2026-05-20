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

// Manager owns the session lifecycle on top of a cookie. It reads and
// writes the cookie through a [security.Carrier], so it works behind the
// HTTP adapter (httpsec) without importing it.
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
}

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

// WithTTL overrides the absolute session lifetime. Default: 24h.
func WithTTL(ttl time.Duration) Option {
	return func(m *Manager) { m.ttl = ttl }
}

// WithIdleTimeout enables an idle-timeout: a session untouched for longer
// than d is treated as expired. Default: 0 (disabled).
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

// Get decodes and validates the session carried by the request. It returns
// [ErrNoSession] when the cookie is absent / undecodable and a wrapped
// expiry error when the session is past its absolute or idle deadline.
// On success it refreshes LastAccessed but does NOT rewrite the cookie —
// call [Manager.Touch] when sliding expiry is desired.
func (m *Manager) Get(ctx context.Context, c security.Carrier) (*Session, error) {
	_, span := otel.Tracer(tracerName).Start(ctx, "session.Manager.Get")
	defer span.End()

	raw := c.Get(m.cookieName)
	if raw == "" {
		return nil, ErrNoSession
	}

	s, err := m.codec.Decode(raw)
	if err != nil {
		return nil, ErrNoSession
	}

	now := m.clock()
	if s.IsExpired(now) || s.IdleExpired(now, m.idleTimeout) {
		return nil, fmt.Errorf("session: %w", security.ErrTokenExpired)
	}

	s.LastAccessed = now
	span.SetAttributes(attribute.String("session.id_hash", hashID(s.ID)))

	return s, nil
}

// Touch re-writes the cookie with a refreshed LastAccessed, implementing
// sliding-window idle expiry. Call it after a successful Get when the
// idle-timeout should reset on activity.
func (m *Manager) Touch(ctx context.Context, c security.Carrier, s *Session) error {
	_, span := otel.Tracer(tracerName).Start(ctx, "session.Manager.Touch")
	defer span.End()

	s.LastAccessed = m.clock()

	return m.writeCookie(c, s)
}

// Rotate issues a new session ID for the current session while preserving
// its Values — the canonical defense against session fixation, to be
// called right after a privilege change (login, step-up auth).
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

// writeCookie encodes s and stages a Set-Cookie header on the carrier.
func (m *Manager) writeCookie(c security.Carrier, s *Session) error {
	value, err := m.codec.Encode(s)
	if err != nil {
		return fmt.Errorf("session: encode: %w", err)
	}

	// MaxAge is derived from the injected clock, not time.Now, so tests
	// driving a fixed clock observe a coherent cookie lifetime. It is
	// floored at 1s — a zero/negative MaxAge would tell the browser to
	// delete the cookie, which is Logout's job, not Login's.
	maxAge := int(s.ExpiresAt.Sub(m.clock()).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}

	cookie := &http.Cookie{
		Name:     m.cookieName,
		Value:    value,
		Path:     m.path,
		Domain:   m.domain,
		Secure:   m.secure,
		HttpOnly: m.httpOnly,
		SameSite: m.sameSite,
		Expires:  s.ExpiresAt,
		MaxAge:   maxAge,
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
