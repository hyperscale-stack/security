// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"math"
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
	// CSRFToken is the random CSRF secret minted with the session and
	// sealed in its (HttpOnly) cookie. Never render it: render
	// [CSRFToken](s), a masked token anew on every call, which
	// [VerifyCSRF] checks — the raw secret does not verify.
	CSRFToken string
	// CreatedAt is the session creation time.
	CreatedAt time.Time
	// LastAccessed is the time the cookie was last written (Login, Touch,
	// Rotate): the idle timeout keys off that written value. Get updates
	// it in memory only.
	LastAccessed time.Time
	// ExpiresAt is the absolute expiry time. Get reports the deadline the
	// Manager enforces: the earlier of the cookie's ExpiresAt and
	// CreatedAt + the Manager's TTL.
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

// IsExpired reports whether the session has passed the ExpiresAt it
// carries. The [Manager] also enforces CreatedAt + its TTL, whichever comes
// first: rely on [Manager.Get], not on IsExpired alone.
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

// GetInt64 returns the integer stored under key and whether there is one
// that fits an int64: an int of any size set in this request, or the
// json.Number it becomes once the cookie round-trips (numbers decode as
// json.Number, so 64-bit IDs keep their precision — never assert float64 on
// a decoded value). A float, a string or an out-of-range number reports
// false: treat a value that is present but unreadable as a refusal, not as
// absent.
func (s *Session) GetInt64(key string) (int64, bool) {
	switch v := s.Values[key].(type) {
	case json.Number:
		n, err := v.Int64()

		return n, err == nil
	case int:
		return int64(v), true
	case int8:
		return int64(v), true
	case int16:
		return int64(v), true
	case int32:
		return int64(v), true
	case int64:
		return v, true
	case uint8:
		return int64(v), true
	case uint16:
		return int64(v), true
	case uint32:
		return int64(v), true
	case uint:
		return int64(v), v <= math.MaxInt64 //nolint:gosec // G115: checked
	case uint64:
		return int64(v), v <= math.MaxInt64 //nolint:gosec // G115: checked
	}

	return 0, false
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
