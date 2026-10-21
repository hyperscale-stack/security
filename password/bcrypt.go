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

// DefaultBCryptMaxCost is the default limit on the cost of a stored bcrypt
// hash (see [WithBCryptMaxCost]): cost 14 runs about one second per
// verification on a contemporary core, 16 times cost 10. Each extra unit
// doubles the time — cost 31 would run for days.
const DefaultBCryptMaxCost = 14

// maxBCryptPasswordLen is the longest password bcrypt processes: longer
// ones would be silently truncated.
const maxBCryptPasswordLen = 72

// BCryptOption configures a [BCryptHasher].
type BCryptOption func(*BCryptHasher)

// WithBCryptMaxCost bounds the cost of the stored hashes Verify accepts:
// the cost is read before any hashing, and a hash above the limit fails with
// [ErrCostLimitExceeded]. The limit is inclusive and raised to the hasher's
// own cost, so a hasher always verifies the hashes it produces. It panics
// outside [bcrypt.MinCost, bcrypt.MaxCost].
func WithBCryptMaxCost(cost int) BCryptOption {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		panic(fmt.Sprintf("password: WithBCryptMaxCost: cost %d outside [%d, %d]", cost, bcrypt.MinCost, bcrypt.MaxCost))
	}

	return func(h *BCryptHasher) { h.maxCost = cost }
}

// BCryptHasher implements [Hasher] on top of golang.org/x/crypto/bcrypt.
// It is the most widely deployed password hash and a good default for
// projects that do not need argon2id-level memory hardness. bcrypt
// processes at most 72 bytes — as few as 18 characters of 4-byte UTF-8 —
// while NIST SP 800-63B-4 §3.1.1.2 asks verifiers to permit passwords of at
// least 64 characters: prefer [Argon2idHasher] for new deployments.
type BCryptHasher struct {
	cost    int
	maxCost int
}

// NewBCryptHasher returns a [Hasher] backed by bcrypt at the given cost.
// Passing 0 selects [bcrypt.DefaultCost] (10, the OWASP minimum); costs
// below 10 are for tests only. A cost outside [bcrypt.MinCost (4),
// bcrypt.MaxCost (31)] panics — it is static configuration, refused at
// start-up. Stored hashes are accepted up to [DefaultBCryptMaxCost] (or
// the hasher's own cost if higher) unless [WithBCryptMaxCost] says
// otherwise.
func NewBCryptHasher(cost int, opts ...BCryptOption) *BCryptHasher {
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}

	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		panic(fmt.Sprintf("password: NewBCryptHasher: cost %d outside [%d, %d]", cost, bcrypt.MinCost, bcrypt.MaxCost))
	}

	h := &BCryptHasher{cost: cost, maxCost: DefaultBCryptMaxCost}

	for _, o := range opts {
		o(h)
	}

	h.maxCost = max(h.maxCost, cost)

	return h
}

// Cost returns the configured bcrypt cost. Useful in tests and for
// observability.
func (h *BCryptHasher) Cost() int { return h.cost }

// MaxCost returns the highest stored cost Verify accepts.
func (h *BCryptHasher) MaxCost() int { return h.maxCost }

// Hash implements [Hasher]. It refuses an empty password
// ([ErrEmptyPassword]) and one longer than 72 bytes ([ErrPasswordTooLong]).
func (h *BCryptHasher) Hash(ctx context.Context, password string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("password: context canceled: %w", err)
	}

	switch {
	case password == "":
		return "", ErrEmptyPassword
	case len(password) > maxBCryptPasswordLen:
		return "", fmt.Errorf("password: bcrypt: %w", ErrPasswordTooLong)
	}

	out, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	if err != nil {
		return "", fmt.Errorf("password: bcrypt hash: %w", err)
	}

	return string(out), nil
}

// Verify implements [Hasher]. The stored hash's algorithm and cost are
// checked before any hashing; a password longer than 72 bytes is refused
// ([ErrPasswordTooLong]) instead of being compared on its first 72 bytes. A
// plain mismatch, and an empty password, return (false, nil).
func (h *BCryptHasher) Verify(ctx context.Context, encodedHash, password string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("password: context canceled: %w", err)
	}

	if err := h.check(encodedHash); err != nil {
		return false, err
	}

	switch {
	case len(password) > maxBCryptPasswordLen:
		return false, fmt.Errorf("password: bcrypt: %w", ErrPasswordTooLong)
	case password == "":
		return false, nil
	}

	err := bcrypt.CompareHashAndPassword([]byte(encodedHash), []byte(password))
	if err == nil {
		return true, nil
	}

	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return false, nil
	}

	return false, fmt.Errorf("password: bcrypt: %w: %w", ErrMalformedHash, err)
}

// NeedsRehash implements [Hasher]: it returns true when the stored cost is
// strictly below the hasher's configured cost (the case after the operator
// raised the security baseline), or when Verify refuses the hash (another
// algorithm, malformed, above the cost limit).
func (h *BCryptHasher) NeedsRehash(encodedHash string) bool {
	if h.check(encodedHash) != nil {
		return true
	}

	cost, _ := bcrypt.Cost([]byte(encodedHash)) // check parsed it already

	return cost < h.cost
}

// check verifies that encodedHash is a bcrypt hash whose cost is within the
// limit, without hashing.
func (h *BCryptHasher) check(encodedHash string) error {
	if !looksLikeBCrypt(encodedHash) {
		return ErrUnsupportedAlgorithm
	}

	cost, err := bcrypt.Cost([]byte(encodedHash))
	if err != nil {
		return fmt.Errorf("password: bcrypt: %w: %w", ErrMalformedHash, err)
	}

	if cost > h.maxCost {
		return fmt.Errorf("%w: bcrypt cost %d above %d", ErrCostLimitExceeded, cost, h.maxCost)
	}

	return nil
}

// looksLikeBCrypt reports whether h is a bcrypt hash of a version this
// hasher verifies: $2a$ (OpenBSD 2.1+), $2b$ (OpenBSD 5.5+) or $2y$
// (crypt_blowfish's correct implementation), which x/crypto computes alike.
// It refuses $2x$ — the prefix crypt_blowfish gives the hashes of its
// sign-extension bug, which x/crypto would verify as $2a$ — and $2$, the
// format before $2a$; other algorithms (argon2id, scrypt) start with
// another prefix.
func looksLikeBCrypt(h string) bool {
	return strings.HasPrefix(h, "$2a$") || strings.HasPrefix(h, "$2b$") || strings.HasPrefix(h, "$2y$")
}
