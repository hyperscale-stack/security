// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session

import (
	"crypto/rand"
	"encoding/base64"
	"time"
)

// schemeName is the canonical label of this authentication scheme: the
// default cookie name, the [Authenticator]'s name, and the fallback
// [Authentication.Name] before a principal is resolved.
const schemeName = "session"

// Session is the unit of state carried across requests of the same browser
// client. With the cookie-backed [Manager] the whole struct is encrypted
// into the cookie value — there is no server-side storage to look up.
type Session struct {
	// ID is a random, unguessable session identifier. It is rotated on
	// privilege changes (see [Manager.Rotate]) to defeat session fixation.
	ID string
	// Values holds application data (user id, tenant, feature flags…).
	// Keep it small: the whole map is JSON-encoded into the cookie, and
	// browsers cap a cookie at ~4 KiB.
	Values map[string]any
	// CSRFToken is a random token minted with the session. It is never
	// exposed to JavaScript (the cookie is HttpOnly); the application
	// echoes it into forms / a meta tag and the csrf helpers verify it.
	CSRFToken string
	// CreatedAt is the session creation time.
	CreatedAt time.Time
	// LastAccessed is refreshed on every successful load; idle-timeout
	// enforcement keys off it.
	LastAccessed time.Time
	// ExpiresAt is the absolute expiry time.
	ExpiresAt time.Time
}

// newSession mints a fresh Session with random ID + CSRF token and the
// supplied lifetimes.
func newSession(now time.Time, ttl time.Duration) (*Session, error) {
	id, err := randomToken(18) // 144 bits
	if err != nil {
		return nil, err
	}

	csrf, err := randomToken(32) // 256 bits
	if err != nil {
		return nil, err
	}

	return &Session{
		ID:           id,
		Values:       map[string]any{},
		CSRFToken:    csrf,
		CreatedAt:    now,
		LastAccessed: now,
		ExpiresAt:    now.Add(ttl),
	}, nil
}

// IsExpired reports whether the session has passed its absolute expiry.
func (s *Session) IsExpired(now time.Time) bool {
	return now.After(s.ExpiresAt)
}

// IdleExpired reports whether more than idle has elapsed since the session
// was last accessed. A zero idle disables the idle-timeout check.
func (s *Session) IdleExpired(now time.Time, idle time.Duration) bool {
	if idle <= 0 {
		return false
	}

	return now.After(s.LastAccessed.Add(idle))
}

// GetString returns the string value stored under key, or "" when absent or
// not a string. The cookie round-trips through JSON, so values written as
// strings come back as strings.
func (s *Session) GetString(key string) string {
	v, _ := s.Values[key].(string)

	return v
}

// randomToken returns n cryptographically-random bytes, base64url-encoded
// without padding.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err //nolint:wrapcheck // caller wraps with package context
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}
