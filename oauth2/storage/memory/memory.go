// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package memory ships an in-process [oauth2.Storage] implementation for
// development and tests. Production deployments MUST use the SQL or Redis
// implementations instead — the in-memory store loses all state on
// restart, and never purges anything: it grows with every code and token
// it is given, since consumed and expired codes, expired tokens and
// revoked families stay in memory for the process lifetime. Like every
// store it keeps codes and tokens hashed only: the raw code or token of a
// record it is handed is never kept, nor returned by a lookup.
//
// All operations are guarded by a single sync.Mutex; the resulting
// throughput is fine for tens of thousands of req/s but the structure is
// optimized for clarity, not for scale.
package memory

import (
	"context"
	"fmt"
	"sync"

	"github.com/hyperscale-stack/security/oauth2"
)

// Store is an in-memory [oauth2.Storage]. The zero value is unusable;
// build one with [New].
//
// The mutex is the linearization point of the token-family contract: every
// issuance, rotation, revocation and lookup checks or records the revoked
// families under it. A family needs no record while it is active, and the
// store never loses one once revoked, so the I8 fail-closed rule of
// [oauth2.Storage] never comes into play.
type Store struct {
	mu        sync.Mutex
	codes     map[string]oauth2.AuthorizationCode
	usedCodes map[string]struct{} // consumed codes, kept in codes
	access    map[string]oauth2.AccessToken
	refresh   map[string]oauth2.RefreshToken
	revoked   map[string]struct{} // revoked token families
}

// New returns a fresh [Store].
func New() *Store {
	return &Store{
		codes:     make(map[string]oauth2.AuthorizationCode),
		usedCodes: make(map[string]struct{}),
		access:    make(map[string]oauth2.AccessToken),
		refresh:   make(map[string]oauth2.RefreshToken),
		revoked:   make(map[string]struct{}),
	}
}

// SaveAuthorizationCode implements [oauth2.AuthorizationCodeStore]. The
// record is kept without the raw code.
func (s *Store) SaveAuthorizationCode(_ context.Context, code *oauth2.AuthorizationCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if code.CodeHash == "" {
		return oauth2.ErrInvalidRequest.WithDescription("storage: empty code hash")
	}

	record := *code
	record.Code = ""
	s.codes[code.CodeHash] = record

	return nil
}

// ConsumeAuthorizationCode implements [oauth2.AuthorizationCodeStore].
// Under the store's mutex it marks the code consumed; the record stays for
// the store's lifetime, and every later call gets an
// [*oauth2.CodeReplayError] carrying it.
func (s *Store) ConsumeAuthorizationCode(_ context.Context, codeHash string) (*oauth2.AuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c, ok := s.codes[codeHash]
	if !ok {
		return nil, oauth2.ErrCodeAlreadyUsed
	}

	if _, used := s.usedCodes[codeHash]; used {
		return nil, &oauth2.CodeReplayError{Record: &c}
	}

	s.usedCodes[codeHash] = struct{}{}

	// Expiry is NOT checked here: the store only guarantees atomic single
	// use. The grant handler validates IsExpired with its injected clock —
	// keeping the check in one place avoids the store and the grant
	// disagreeing on "now".
	return &c, nil
}

// SaveTokenPair implements [oauth2.Storage]: under the store's mutex it
// refuses a pair joining a revoked family, then persists both tokens.
func (s *Store) SaveTokenPair(_ context.Context, pair *oauth2.TokenPair) error {
	if err := pair.Validate(); err != nil {
		return fmt.Errorf("memory: save token pair: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isRevoked(pair.Access.FamilyID) {
		return oauth2.ErrTokenFamilyRevoked
	}

	s.persist(pair)

	return nil
}

// LookupAccessToken implements [oauth2.AccessTokenStore]. A token of a
// revoked family is reported as [oauth2.ErrTokenFamilyRevoked].
func (s *Store) LookupAccessToken(_ context.Context, tokenHash string) (*oauth2.AccessToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.access[tokenHash]
	if !ok {
		return nil, oauth2.ErrInvalidGrant.WithDescription("access token not found")
	}

	if s.isRevoked(t.FamilyID) {
		return nil, oauth2.ErrTokenFamilyRevoked
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

// LookupRefreshToken implements [oauth2.RefreshTokenStore]. A token of a
// revoked family — or outside any family, which no valid pair carries —
// comes back consumed.
func (s *Store) LookupRefreshToken(_ context.Context, tokenHash string) (*oauth2.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.refresh[tokenHash]
	if !ok {
		return nil, oauth2.ErrInvalidGrant.WithDescription("refresh token not found")
	}

	cp := t
	if cp.FamilyID == "" || s.isRevoked(cp.FamilyID) {
		cp.Consumed = true
	}

	return &cp, nil
}

// RotateRefreshToken implements [oauth2.RefreshTokenStore]. Under the
// store's mutex it decides, in the contract's order: unknown token
// (invalid_grant), next in another family or carrying another grant
// context (invalid_request), revoked family ([oauth2.ErrTokenFamilyRevoked]),
// consumed token (reuse: the family is revoked in the same critical
// section, which cannot fail, and [oauth2.ErrRefreshTokenReused] is
// returned). Otherwise it consumes the old token and persists next.
func (s *Store) RotateRefreshToken(_ context.Context, oldHash string, next *oauth2.TokenPair) error {
	if err := validateRotation(next); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	old, ok := s.refresh[oldHash]

	switch {
	case !ok:
		return oauth2.ErrInvalidGrant.WithDescription("refresh token not found")
	case old.FamilyID != next.Access.FamilyID:
		return oauth2.ErrInvalidRequest.WithDescription("storage: rotation into another token family")
	case old.Issuer != next.Access.Issuer || old.ExtensionData != next.Access.ExtensionData:
		return oauth2.ErrInvalidRequest.WithDescription("storage: rotation into another grant context")
	case s.isRevoked(old.FamilyID):
		return oauth2.ErrTokenFamilyRevoked
	case old.Consumed:
		s.revoked[old.FamilyID] = struct{}{}

		return oauth2.ErrRefreshTokenReused
	}

	old.Consumed = true
	s.refresh[oldHash] = old
	s.persist(next)

	return nil
}

// RevokeRefreshFamily implements [oauth2.RefreshTokenStore]: it records
// the family as revoked, whether or not any of its tokens exists.
func (s *Store) RevokeRefreshFamily(_ context.Context, familyID string) error {
	switch {
	case familyID == "":
		return oauth2.ErrInvalidRequest.WithDescription("storage: empty token family id")
	case len(familyID) > oauth2.MaxFamilyIDLength:
		return oauth2.ErrInvalidRequest.WithDescription("storage: token family id too long")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.revoked[familyID] = struct{}{}

	return nil
}

// isRevoked reports whether familyID is a revoked family; tokens outside
// any family never are. The caller holds the mutex.
func (s *Store) isRevoked(familyID string) bool {
	if familyID == "" {
		return false
	}

	_, revoked := s.revoked[familyID]

	return revoked
}

// persist writes the tokens of pair — copies without their raw value: the
// store keeps hashes only, and leaves the caller's pair untouched. The
// caller holds the mutex.
func (s *Store) persist(pair *oauth2.TokenPair) {
	access := pair.Access
	access.Token = ""
	s.access[access.TokenHash] = access

	if pair.Refresh != nil {
		refresh := *pair.Refresh
		refresh.Token = ""
		s.refresh[refresh.TokenHash] = refresh
	}
}

// validateRotation refuses a malformed rotation target before the store is
// touched: nil, failing [oauth2.TokenPair.Validate], or without the refresh
// token a rotation must issue.
func validateRotation(next *oauth2.TokenPair) error {
	if err := next.Validate(); err != nil {
		return fmt.Errorf("memory: rotate refresh token: %w", err)
	}

	if next.Refresh == nil {
		return oauth2.ErrInvalidRequest.WithDescription("storage: rotation without a refresh token")
	}

	return nil
}

// Compile-time interface check.
var _ oauth2.Storage = (*Store)(nil)
