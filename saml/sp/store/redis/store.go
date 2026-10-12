// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package redisstore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	samlsp "github.com/hyperscale-stack/security/saml/sp"
)

// Store is a Redis-backed samlsp.Storage (see the package documentation).
type Store struct {
	rdb    redis.UniversalClient
	prefix string
}

// Option configures a Store.
type Option func(*Store)

// WithKeyPrefix overrides the key namespace (default "samlsp:").
func WithKeyPrefix(prefix string) Option {
	return func(s *Store) { s.prefix = prefix }
}

// New returns a Store bound to rdb; the caller owns its lifecycle.
func New(rdb redis.UniversalClient, opts ...Option) (*Store, error) {
	if rdb == nil {
		return nil, errors.New("redisstore: New: nil redis client")
	}

	s := &Store{rdb: rdb, prefix: "samlsp:"}
	for _, o := range opts {
		o(s)
	}

	return s, nil
}

func (s *Store) txKey(id string) string         { return s.prefix + "tx:" + id }
func (s *Store) assertionKey(key string) string { return s.prefix + "as:" + key }

// Script replies.
const (
	replyOK       = "ok"
	replyExists   = "exists"
	replyNotFound = "notfound"
	replyConsumed = "consumed"
	replyMismatch = "mismatch"
	replyReplay   = "replay"
)

// saveScript stores a transaction unless its key exists; a resent call
// (same binding and payload) is recognized.
//
//	KEYS[1] tx; ARGV[1] binding; ARGV[2] payload; ARGV[3] expiry (Unix s);
//	ARGV[4] expiry (Unix ms); ARGV[5] integrity
var saveScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 1 then
  if redis.call('HGET', KEYS[1], 'b') == ARGV[1] and redis.call('HGET', KEYS[1], 'p') == ARGV[2] then
    return 'ok'
  end
  return 'exists'
end
redis.call('HSET', KEYS[1], 'b', ARGV[1], 'p', ARGV[2], 'e', ARGV[3], 'i', ARGV[5])
redis.call('PEXPIREAT', KEYS[1], ARGV[4])
return 'ok'
`)

// consumeScript consumes a transaction once, for the matching binding. The
// consuming call's nonce is recorded so that a resent call still sees its
// own success. HSET keeps the key's expiry.
//
//	KEYS[1] tx; ARGV[1] binding; ARGV[2] nonce
var consumeScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return 'notfound' end
local by = redis.call('HGET', KEYS[1], 'c')
if by then
  if by == ARGV[2] then return 'ok' end
  return 'consumed'
end
if redis.call('HGET', KEYS[1], 'b') ~= ARGV[1] then return 'mismatch' end
redis.call('HSET', KEYS[1], 'c', ARGV[2])
return 'ok'
`)

// markScript records an assertion unless present; a resent call is
// recognized by its nonce.
//
//	KEYS[1] assertion; ARGV[1] nonce; ARGV[2] expiry (Unix ms)
var markScript = redis.NewScript(`
if redis.call('SET', KEYS[1], ARGV[1], 'NX') then
  redis.call('PEXPIREAT', KEYS[1], ARGV[2])
  return 'ok'
end
if redis.call('GET', KEYS[1]) == ARGV[1] then return 'ok' end
return 'replay'
`)

// nonce returns a random call identifier.
func nonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // crypto/rand never fails (Go 1.24+)

	return hex.EncodeToString(b)
}

// SaveTransaction implements samlsp.TransactionStore.
func (s *Store) SaveTransaction(ctx context.Context, rec *samlsp.TransactionRecord) error {
	if err := rec.Validate(); err != nil {
		return fmt.Errorf("redisstore: save transaction: %w", err)
	}

	reply, err := saveScript.Run(ctx, s.rdb, []string{s.txKey(rec.ID)},
		rec.BindingHash, rec.Payload, rec.ExpiresAt.Unix(), rec.ExpiresAt.UnixMilli(), rec.Integrity).Text()
	if err != nil {
		return fmt.Errorf("redisstore: save transaction: %w", err)
	}

	switch reply {
	case replyOK:
		return nil
	case replyExists:
		return samlsp.ErrTransactionExists
	default:
		return fmt.Errorf("redisstore: save transaction: unexpected reply %q", reply)
	}
}

// LookupTransaction implements samlsp.TransactionStore.
func (s *Store) LookupTransaction(ctx context.Context, id string) (*samlsp.TransactionRecord, error) {
	if err := samlsp.ValidateStoreKey(id); err != nil {
		return nil, fmt.Errorf("redisstore: lookup transaction: %w", err)
	}

	values, err := s.rdb.HMGet(ctx, s.txKey(id), "b", "p", "e", "c", "i").Result()
	if err != nil {
		return nil, fmt.Errorf("redisstore: lookup transaction: %w", err)
	}

	binding, okB := values[0].(string)
	payload, okP := values[1].(string)
	expiry, okE := values[2].(string)
	integrity, _ := values[4].(string) // absent: refused by the SP (ErrTransactionIntegrity)

	switch {
	case !okB || !okP || !okE:
		return nil, samlsp.ErrTransactionNotFound
	case values[3] != nil:
		return nil, samlsp.ErrTransactionConsumed
	}

	seconds, err := strconv.ParseInt(expiry, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("redisstore: lookup transaction: corrupt expiry: %w", err)
	}

	return &samlsp.TransactionRecord{
		ID: id, BindingHash: binding, Payload: payload, ExpiresAt: time.Unix(seconds, 0), Integrity: integrity,
	}, nil
}

// ConsumeTransaction implements samlsp.TransactionStore.
func (s *Store) ConsumeTransaction(ctx context.Context, id, bindingHash string) error {
	if err := samlsp.ValidateStoreKey(id); err != nil {
		return fmt.Errorf("redisstore: consume transaction: %w", err)
	}

	if err := samlsp.ValidateStoreKey(bindingHash); err != nil {
		return fmt.Errorf("redisstore: consume transaction: %w", err)
	}

	reply, err := consumeScript.Run(ctx, s.rdb, []string{s.txKey(id)}, bindingHash, nonce()).Text()
	if err != nil {
		return fmt.Errorf("redisstore: consume transaction: %w", err)
	}

	switch reply {
	case replyOK:
		return nil
	case replyNotFound:
		return samlsp.ErrTransactionNotFound
	case replyConsumed:
		return samlsp.ErrTransactionConsumed
	case replyMismatch:
		return samlsp.ErrBrowserBindingMismatch
	default:
		return fmt.Errorf("redisstore: consume transaction: unexpected reply %q", reply)
	}
}

// MarkAssertionUsed implements samlsp.ReplayCache.
func (s *Store) MarkAssertionUsed(ctx context.Context, key string, expiresAt time.Time) error {
	if err := samlsp.ValidateStoreKey(key); err != nil {
		return fmt.Errorf("redisstore: mark assertion: %w", err)
	}

	if err := samlsp.ValidateExpiry(expiresAt); err != nil {
		return fmt.Errorf("redisstore: mark assertion: %w", err)
	}

	reply, err := markScript.Run(ctx, s.rdb, []string{s.assertionKey(key)}, nonce(), expiresAt.UnixMilli()).Text()
	if err != nil {
		return fmt.Errorf("redisstore: mark assertion: %w", err)
	}

	switch reply {
	case replyOK:
		return nil
	case replyReplay:
		return samlsp.ErrAssertionReplayed
	default:
		return fmt.Errorf("redisstore: mark assertion: unexpected reply %q", reply)
	}
}
