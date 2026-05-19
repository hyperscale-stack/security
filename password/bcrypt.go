// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package password

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// BCryptHasher implements [Hasher] on top of golang.org/x/crypto/bcrypt.
// It is the most widely deployed password hash and a good default for
// projects that do not need argon2id-level memory hardness.
type BCryptHasher struct {
	cost int
}

// NewBCryptHasher returns a [Hasher] backed by bcrypt at the given cost.
// Cost values below [bcrypt.MinCost] are clamped to bcrypt.MinCost; values
// above [bcrypt.MaxCost] are clamped to bcrypt.MaxCost. Passing 0 yields
// [bcrypt.DefaultCost] (12 as of bcrypt v0.x).
func NewBCryptHasher(cost int) *BCryptHasher {
	switch {
	case cost == 0:
		cost = bcrypt.DefaultCost
	case cost < bcrypt.MinCost:
		cost = bcrypt.MinCost
	case cost > bcrypt.MaxCost:
		cost = bcrypt.MaxCost
	}

	return &BCryptHasher{cost: cost}
}

// Cost returns the configured bcrypt cost. Useful in tests and for
// observability.
func (h *BCryptHasher) Cost() int { return h.cost }

// Hash implements [Hasher].
func (h *BCryptHasher) Hash(ctx context.Context, password string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("password: context canceled: %w", err)
	}

	out, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	if err != nil {
		return "", fmt.Errorf("password: bcrypt hash: %w", err)
	}

	return string(out), nil
}

// Verify implements [Hasher]. A plain mismatch returns (false, nil).
func (h *BCryptHasher) Verify(ctx context.Context, encodedHash, password string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("password: context canceled: %w", err)
	}

	if !looksLikeBCrypt(encodedHash) {
		return false, ErrUnsupportedAlgorithm
	}

	err := bcrypt.CompareHashAndPassword([]byte(encodedHash), []byte(password))
	if err == nil {
		return true, nil
	}

	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return false, nil
	}

	return false, fmt.Errorf("password: bcrypt compare: %w", err)
}

// NeedsRehash implements [Hasher]: it returns true when the stored cost is
// strictly below the hasher's configured cost (the case after the operator
// raised the security baseline) or when the encoded hash is not a bcrypt
// blob at all (e.g. migration from another algorithm).
func (h *BCryptHasher) NeedsRehash(encodedHash string) bool {
	if !looksLikeBCrypt(encodedHash) {
		return true
	}

	cost, err := bcrypt.Cost([]byte(encodedHash))
	if err != nil {
		return true
	}

	return cost < h.cost
}

// looksLikeBCrypt is a cheap discriminator: every bcrypt blob starts with
// "$2", whether it's $2a (Wing/Sun reference), $2b (OpenBSD ≥ 5.5) or $2y
// (PHP-friendly variant). Other algorithms (argon2id, scrypt, plain) start
// with another prefix.
func looksLikeBCrypt(h string) bool {
	return strings.HasPrefix(h, "$2")
}
