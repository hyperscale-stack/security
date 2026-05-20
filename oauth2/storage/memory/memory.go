// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package memory ships an in-process [oauth2.Storage] implementation
// suitable for tests, examples and small single-instance deployments.
// Production deployments MUST use the SQL or Redis implementations
// instead — the in-memory store loses all state on restart.
//
// All operations are guarded by a single sync.Mutex; the resulting
// throughput is fine for tens of thousands of req/s but the structure is
// optimized for clarity, not for scale.
package memory

import (
	"context"
	"sync"

	"github.com/hyperscale-stack/security/oauth2"
)

// Store is an in-memory [oauth2.Storage]. The zero value is unusable;
// build one with [New].
type Store struct {
	mu       sync.Mutex
	codes    map[string]oauth2.AuthorizationCode
	access   map[string]oauth2.AccessToken
	refresh  map[string]oauth2.RefreshToken
	families map[string][]string // familyID -> refresh-token hashes (for revocation)
}

// New returns a fresh [Store].
func New() *Store {
	return &Store{
		codes:    make(map[string]oauth2.AuthorizationCode),
		access:   make(map[string]oauth2.AccessToken),
		refresh:  make(map[string]oauth2.RefreshToken),
		families: make(map[string][]string),
	}
}

// SaveAuthorizationCode implements [oauth2.AuthorizationCodeStore].
func (s *Store) SaveAuthorizationCode(_ context.Context, code *oauth2.AuthorizationCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if code.CodeHash == "" {
		return oauth2.ErrInvalidRequest.WithDescription("storage: empty code hash")
	}

	s.codes[code.CodeHash] = *code

	return nil
}

// ConsumeAuthorizationCode implements [oauth2.AuthorizationCodeStore]. The
// operation is atomic under the store's mutex.
func (s *Store) ConsumeAuthorizationCode(_ context.Context, codeHash string) (*oauth2.AuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c, ok := s.codes[codeHash]
	if !ok {
		return nil, oauth2.ErrCodeAlreadyUsed
	}

	delete(s.codes, codeHash)

	// Expiry is NOT checked here: the store only guarantees atomic
	// single-use read+delete. The grant handler validates IsExpired with
	// its injected clock — keeping the check in one place avoids the
	// store and the grant disagreeing on "now".
	cp := c

	return &cp, nil
}

// SaveAccessToken implements [oauth2.AccessTokenStore].
func (s *Store) SaveAccessToken(_ context.Context, t *oauth2.AccessToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if t.TokenHash == "" {
		return oauth2.ErrInvalidRequest.WithDescription("storage: empty access token hash")
	}

	s.access[t.TokenHash] = *t

	return nil
}

// LookupAccessToken implements [oauth2.AccessTokenStore].
func (s *Store) LookupAccessToken(_ context.Context, tokenHash string) (*oauth2.AccessToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.access[tokenHash]
	if !ok {
		return nil, oauth2.ErrInvalidGrant.WithDescription("access token not found")
	}

	cp := t

	return &cp, nil
}

// RevokeAccessToken implements [oauth2.AccessTokenStore].
func (s *Store) RevokeAccessToken(_ context.Context, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.access, tokenHash)

	return nil
}

// SaveRefreshToken implements [oauth2.RefreshTokenStore]. The token is
// registered in its family so that subsequent revocation can iterate every
// sibling.
func (s *Store) SaveRefreshToken(_ context.Context, t *oauth2.RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if t.TokenHash == "" {
		return oauth2.ErrInvalidRequest.WithDescription("storage: empty refresh token hash")
	}

	s.refresh[t.TokenHash] = *t

	if t.FamilyID != "" {
		s.families[t.FamilyID] = append(s.families[t.FamilyID], t.TokenHash)
	}

	return nil
}

// LookupRefreshToken implements [oauth2.RefreshTokenStore].
func (s *Store) LookupRefreshToken(_ context.Context, tokenHash string) (*oauth2.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.refresh[tokenHash]
	if !ok {
		return nil, oauth2.ErrInvalidGrant.WithDescription("refresh token not found")
	}

	cp := t

	return &cp, nil
}

// RotateRefreshToken implements [oauth2.RefreshTokenStore]. The atomic
// sequence under the store's mutex is:
//
//  1. Look up the old token; if missing -> ErrInvalidGrant.
//  2. If the old token is already consumed -> revoke the entire family and
//     return [oauth2.ErrRefreshTokenReused] (BCP §8.10.3).
//  3. Mark the old token as consumed, save the new token, register it in
//     the same family.
func (s *Store) RotateRefreshToken(ctx context.Context, oldHash string, next *oauth2.RefreshToken) error {
	s.mu.Lock()

	old, ok := s.refresh[oldHash]
	if !ok {
		s.mu.Unlock()

		return oauth2.ErrInvalidGrant.WithDescription("refresh token not found")
	}

	if old.Consumed {
		family := old.FamilyID

		s.mu.Unlock()

		_ = s.RevokeRefreshFamily(ctx, family)

		return oauth2.ErrRefreshTokenReused
	}

	old.Consumed = true
	s.refresh[oldHash] = old
	s.refresh[next.TokenHash] = *next

	if next.FamilyID != "" {
		s.families[next.FamilyID] = append(s.families[next.FamilyID], next.TokenHash)
	}

	s.mu.Unlock()

	return nil
}

// RevokeRefreshFamily implements [oauth2.RefreshTokenStore]. Every refresh
// token in the family is marked consumed and every access token whose
// FamilyID matches is removed.
func (s *Store) RevokeRefreshFamily(_ context.Context, familyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, hash := range s.families[familyID] {
		if t, ok := s.refresh[hash]; ok {
			t.Consumed = true
			s.refresh[hash] = t
		}
	}

	for hash, t := range s.access {
		if t.FamilyID == familyID {
			delete(s.access, hash)
		}
	}

	return nil
}

// Compile-time interface check.
var _ oauth2.Storage = (*Store)(nil)
