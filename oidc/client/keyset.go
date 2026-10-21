// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// JWK Set cache policy.
const (
	// keySetTTL is the age after which the next use fetches the set again:
	// it bounds how long a key the provider withdrew stays accepted while
	// the JWK Set endpoint answers — the DefaultCacheTTL of the jwt
	// module's remote key sets.
	keySetTTL = 5 * time.Minute
	// keySetMinRefresh is the minimum time between two fetch attempts: a
	// stream of unknown kids — a hostile tenant-configured provider —
	// cannot make the Client fetch more often.
	keySetMinRefresh = 10 * time.Second
	// keySetMaxStale is the age after which a cached set is no longer used
	// while fetches fail: verification then fails closed. Until then, an
	// attacker holding a key the provider withdrew and able to make the
	// fetches fail keeps it trusted; rebuilding the Client drops it.
	keySetMaxStale = 24 * time.Hour
)

// errNoKeySet reports that no JWK Set was ever retrieved.
var errNoKeySet = errors.New("no JWK Set retrieved yet")

// keySet caches the provider's JWK Set, refreshed lazily — on first use,
// after keySetTTL, and on an unknown kid (OpenID Connect Core §10.1.1) —
// at most once per keySetMinRefresh, with concurrent callers sharing one
// fetch. It starts no goroutine of its own beyond the fetch in flight.
type keySet struct {
	client *http.Client
	uri    string
	now    func() time.Time

	mu          sync.Mutex
	keys        []verificationKey
	fetchedAt   time.Time // last successful fetch, zero before the first
	lastAttempt time.Time // last completed fetch attempt
	lastErr     error     // error of the last failed attempt, errNoKeySet before any
	inflight    *keyFetch
}

// keyFetch is a fetch in flight; done is closed once err is set.
type keyFetch struct {
	done chan struct{}
	err  error
}

func newKeySet(client *http.Client, uri string, now func() time.Time) *keySet {
	return &keySet{client: client, uri: uri, now: now, lastErr: errNoKeySet}
}

// current returns the cached keys, refreshing them first when none were
// fetched yet or they are older than keySetTTL. A failed refresh keeps the
// previous keys until they are older than keySetMaxStale.
func (s *keySet) current(ctx context.Context) ([]verificationKey, error) {
	if s.expired() {
		if _, err := s.refresh(ctx); err != nil && ctx.Err() != nil {
			return nil, err
		}
	}

	return s.usable()
}

func (s *keySet) expired() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.fetchedAt.IsZero() || !s.now().Before(s.fetchedAt.Add(keySetTTL))
}

// usable returns the cached keys unless there are none or they are too old.
func (s *keySet) usable() ([]verificationKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if keys := s.fresh(); keys != nil {
		return keys, nil
	}

	return nil, fmt.Errorf("%w: %w", ErrKeySet, s.lastErr)
}

// snapshot returns the usable keys, nil when there are none.
func (s *keySet) snapshot() []verificationKey {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.fresh()
}

// fresh returns the cached keys unless none were fetched or they are older
// than keySetMaxStale. The caller holds the mutex.
func (s *keySet) fresh() []verificationKey {
	if s.fetchedAt.IsZero() || s.now().Sub(s.fetchedAt) > keySetMaxStale {
		return nil
	}

	return s.keys // never nil once fetched: parseKeySet returns a non-nil slice
}

// refresh fetches the set again, or joins the fetch in flight, unless the
// last attempt completed less than keySetMinRefresh ago. It reports whether
// a fetch completed for the caller. The fetch runs on a context detached
// from the caller's — bounded by the outbound timeout — so that a caller
// giving up does not abort it for the others nor burn the rate limit;
// the caller itself stops waiting when its context ends.
func (s *keySet) refresh(ctx context.Context) (bool, error) {
	s.mu.Lock()

	call := s.inflight
	if call == nil {
		if !s.lastAttempt.IsZero() && s.now().Sub(s.lastAttempt) < keySetMinRefresh {
			s.mu.Unlock()

			return false, nil
		}

		call = &keyFetch{done: make(chan struct{})}
		s.inflight = call

		go s.fetch(context.WithoutCancel(ctx), call)
	}

	s.mu.Unlock()

	select {
	case <-call.done:
		return true, call.err
	case <-ctx.Done():
		return false, fmt.Errorf("oidcclient: waiting for the JWK Set: %w", ctx.Err())
	}
}

// fetch downloads the set and publishes the outcome to call.
func (s *keySet) fetch(ctx context.Context, call *keyFetch) {
	keys, err := s.download(ctx)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.lastAttempt = s.now()

	if err == nil {
		s.keys, s.fetchedAt = keys, s.lastAttempt
	} else {
		s.lastErr = err
	}

	s.inflight = nil
	call.err = err
	close(call.done)
}

func (s *keySet) download(ctx context.Context) ([]verificationKey, error) {
	body, err := fetchJSON(ctx, s.client, s.uri, mediaJSON, "application/jwk-set+json")
	if err != nil {
		return nil, err
	}

	return parseKeySet(body)
}
